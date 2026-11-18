#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Privileges: least privilege by default, table and global grants, revoke, grant option.

use novadb_sql::{Engine, Session, SqlError};

struct Db {
    dir: std::path::PathBuf,
    e: Option<Engine>,
}

impl Db {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("novadb-privs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let e = Engine::open(&dir)
            .unwrap()
            .with_password_hasher(|p| Ok(format!("h:{p}")))
            .with_privileges();
        let mut e = e;
        e.set_user_hash("root", "h:root-password-1").unwrap(); // the server creates root at first start
        Db { dir, e: Some(e) }
    }
    fn as_user(&mut self, user: &str, sql: &str) -> Result<Vec<String>, SqlError> {
        let mut s = Session {
            user: user.into(),
            conn_id: 7,
            ..Default::default()
        };
        let mut out = Vec::new();
        for st in novadb_sql::parse(sql)? {
            let r = self.e.as_mut().unwrap().run_in(&st, &mut s)?;
            out = (0..r.rows.len())
                .map(|i| {
                    (0..r.columns.len())
                        .map(|c| r.text(i, c).unwrap_or_else(|| "NULL".into()))
                        .collect::<Vec<_>>()
                        .join("|")
                })
                .collect();
        }
        Ok(out)
    }
    fn root(&mut self, sql: &str) -> Vec<String> {
        self.as_user("root", sql)
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }
    fn code(&mut self, user: &str, sql: &str) -> u16 {
        match self.as_user(user, sql) {
            Ok(r) => panic!("{user}: {sql} should be denied, got {r:?}"),
            Err(e) => e.code,
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        if let Some(e) = self.e.take() {
            let _ = e.close();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn least_privilege_and_table_grants() {
    let mut d = Db::new("tables");
    d.root("CREATE TABLE orders (id INT PRIMARY KEY, total INT); CREATE TABLE secrets (k INT PRIMARY KEY, v VARCHAR(10))");
    d.root("INSERT INTO orders VALUES (1, 10); INSERT INTO secrets VALUES (1, 'x')");
    d.root("CREATE USER app IDENTIFIED BY 'app-password-123'");
    // A new user can do nothing but harmless session statements.
    assert_eq!(d.code("app", "SELECT * FROM orders"), 1142);
    assert_eq!(d.code("app", "INSERT INTO orders VALUES (2, 1)"), 1142);
    assert_eq!(d.code("app", "CREATE TABLE mine (x INT)"), 1142);
    assert_eq!(d.code("app", "DROP TABLE orders"), 1142);
    assert_eq!(
        d.code("app", "CREATE USER evil IDENTIFIED BY 'evil-password-1'"),
        1227
    );
    assert_eq!(d.as_user("app", "SELECT 1 + 1").unwrap(), vec!["2"]);
    assert!(
        d.as_user("app", "SHOW TABLES").unwrap().is_empty(),
        "no table names leak"
    );
    assert_eq!(
        d.as_user("app", "SHOW GRANTS").unwrap(),
        vec!["GRANT USAGE ON *.* TO `app`@`%`"]
    );

    // Table-level read + write on one table only.
    d.root("GRANT SELECT, INSERT, UPDATE ON orders TO app");
    assert_eq!(
        d.as_user("app", "SELECT total FROM orders").unwrap(),
        vec!["10"]
    );
    d.as_user(
        "app",
        "INSERT INTO orders VALUES (2, 20); UPDATE orders SET total = 11 WHERE id = 1",
    )
    .unwrap();
    assert_eq!(d.code("app", "DELETE FROM orders WHERE id = 1"), 1142);
    assert_eq!(d.code("app", "SELECT * FROM secrets"), 1142);
    // Every table a statement touches is checked: joins, subqueries, INSERT … SELECT.
    assert_eq!(
        d.code(
            "app",
            "SELECT o.id FROM orders o JOIN secrets s ON s.k = o.id"
        ),
        1142
    );
    assert_eq!(
        d.code(
            "app",
            "SELECT id FROM orders WHERE id IN (SELECT k FROM secrets)"
        ),
        1142
    );
    assert_eq!(
        d.code("app", "INSERT INTO orders SELECT k + 100, 0 FROM secrets"),
        1142
    );
    assert_eq!(
        d.code(
            "app",
            "UPDATE orders SET total = (SELECT COUNT(*) FROM secrets)"
        ),
        1142
    );
    assert_eq!(d.as_user("app", "SHOW TABLES").unwrap(), vec!["orders"]);
    assert_eq!(d.code("app", "DESCRIBE secrets"), 1142);
    assert_eq!(
        d.as_user("app", "SHOW GRANTS").unwrap(),
        vec![
            "GRANT USAGE ON *.* TO `app`@`%`",
            "GRANT SELECT, INSERT, UPDATE ON `novadb`.`orders` TO `app`@`%`"
        ]
    );
    // Users may change their own password, not anyone else's.
    d.as_user("app", "ALTER USER app IDENTIFIED BY 'new-app-password-1'")
        .unwrap();
    assert_eq!(
        d.code("app", "ALTER USER root IDENTIFIED BY 'stolen-password-1'"),
        1227
    );
    assert_eq!(d.code("app", "GRANT SELECT ON secrets TO app"), 1227);

    // Revoke.
    d.root("REVOKE INSERT, UPDATE ON orders FROM app");
    assert_eq!(d.code("app", "INSERT INTO orders VALUES (3, 1)"), 1142);
    assert_eq!(
        d.as_user("app", "SELECT COUNT(*) FROM orders").unwrap(),
        vec!["2"]
    );
    // Global grants and ALL PRIVILEGES.
    d.root("GRANT ALL PRIVILEGES ON *.* TO app");
    d.as_user(
        "app",
        "SELECT * FROM secrets; CREATE TABLE mine (x INT); DROP TABLE mine",
    )
    .unwrap();
    d.root("REVOKE ALL PRIVILEGES ON *.* FROM app");
    assert_eq!(d.code("app", "SELECT * FROM secrets"), 1142);
    // Global-only privileges cannot be granted on a table.
    assert_eq!(
        d.as_user("root", "GRANT PROCESS ON orders TO app")
            .unwrap_err()
            .code,
        1144
    );
    // DROP USER removes grants; a recreated user starts empty.
    d.root("DROP USER app; CREATE USER app IDENTIFIED BY 'app-password-123'");
    assert_eq!(d.code("app", "SELECT * FROM orders"), 1142);
    assert_eq!(
        d.as_user("root", "GRANT SELECT ON orders TO nobody")
            .unwrap_err()
            .code,
        1410
    );
}

#[test]
fn grant_option_delegation() {
    let mut d = Db::new("delegate");
    d.root("CREATE TABLE t (id INT PRIMARY KEY); CREATE TABLE u (id INT PRIMARY KEY)");
    d.root("CREATE USER lead IDENTIFIED BY 'lead-password-123'; CREATE USER dev IDENTIFIED BY 'dev-password-1234'");
    d.root("GRANT SELECT, INSERT ON t TO lead WITH GRANT OPTION");
    d.as_user("lead", "GRANT SELECT ON t TO dev").unwrap();
    d.as_user("dev", "SELECT * FROM t").unwrap();
    // Cannot hand out more than you have, or on other tables.
    assert_eq!(d.code("lead", "GRANT DELETE ON t TO dev"), 1227);
    assert_eq!(d.code("lead", "GRANT SELECT ON u TO dev"), 1227);
    // dev has no GRANT OPTION.
    assert_eq!(d.code("dev", "GRANT SELECT ON t TO lead"), 1227);
    d.root("REVOKE GRANT OPTION ON t FROM lead");
    assert_eq!(d.code("lead", "GRANT INSERT ON t TO dev"), 1227);
    assert_eq!(d.code("lead", "SHOW GRANTS FOR dev"), 1227);
}
