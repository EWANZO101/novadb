#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Stage 6: joins, aggregates, GROUP BY/HAVING, subqueries, INSERT … SELECT, interrupts.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use novadb_sql::{Engine, QueryResult};

struct Db {
    dir: std::path::PathBuf,
    e: Option<Engine>,
}

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl Db {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("novadb-query-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Db {
            e: Some(Engine::open(&dir).unwrap()),
            dir,
        }
    }
    fn q(&mut self, sql: &str) -> QueryResult {
        self.e
            .as_mut()
            .unwrap()
            .query(sql)
            .unwrap_or_else(|e| panic!("{sql}\n -> {e}"))
    }
    fn err(&mut self, sql: &str) -> u16 {
        match self.e.as_mut().unwrap().query(sql) {
            Ok(r) => panic!("{sql} should fail, got {r:?}"),
            Err(e) => e.code,
        }
    }
    fn rows(&mut self, sql: &str) -> Vec<String> {
        let r = self.q(sql);
        (0..r.rows.len())
            .map(|i| {
                (0..r.columns.len())
                    .map(|c| r.text(i, c).unwrap_or_else(|| "NULL".into()))
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect()
    }
    fn exec(&mut self, sql: &str) {
        self.e
            .as_mut()
            .unwrap()
            .execute(sql)
            .unwrap_or_else(|e| panic!("{sql}\n -> {e}"));
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

fn shop() -> Db {
    let mut d = Db::new();
    d.exec(
        "CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(20), city VARCHAR(20));
         CREATE TABLE orders (id INT PRIMARY KEY, cust INT, total DECIMAL(8,2), status VARCHAR(10), KEY kc (cust));
         CREATE TABLE items (order_id INT, sku VARCHAR(10), qty INT, PRIMARY KEY (order_id, sku));
         INSERT INTO customers VALUES (1,'ann','paris'),(2,'bob','rome'),(3,'cat','paris'),(4,'dan',NULL);
         INSERT INTO orders VALUES (10,1,20.00,'paid'),(11,1,5.50,'open'),(12,2,100.00,'paid'),(13,3,NULL,'open'),(14,99,1.00,'paid');
         INSERT INTO items VALUES (10,'a',2),(10,'b',1),(11,'a',5),(12,'c',1),(14,'a',1);",
    );
    d
}

#[test]
fn inner_left_right_cross_using() {
    let mut d = shop();
    assert_eq!(
        d.rows("SELECT c.name, o.id FROM customers c JOIN orders o ON o.cust = c.id ORDER BY o.id"),
        vec!["ann|10", "ann|11", "bob|12", "cat|13"]
    );
    assert_eq!(
        d.rows("SELECT c.name, o.id FROM customers AS c LEFT JOIN orders AS o ON o.cust = c.id ORDER BY c.id, o.id"),
        vec!["ann|10", "ann|11", "bob|12", "cat|13", "dan|NULL"]
    );
    // WHERE on the right side of a LEFT JOIN filters after NULL-extension; ON does not.
    assert_eq!(
        d.rows(
            "SELECT c.name FROM customers c LEFT JOIN orders o ON o.cust = c.id WHERE o.id IS NULL"
        ),
        vec!["dan"]
    );
    assert_eq!(
        d.rows("SELECT c.name, o.id FROM customers c LEFT JOIN orders o ON o.cust = c.id AND o.status = 'paid' ORDER BY c.id"),
        vec!["ann|10", "bob|12", "cat|NULL", "dan|NULL"]
    );
    assert_eq!(
        d.rows("SELECT o.id, c.name FROM customers c RIGHT JOIN orders o ON o.cust = c.id ORDER BY o.id"),
        vec!["10|ann", "11|ann", "12|bob", "13|cat", "14|NULL"]
    );
    assert_eq!(d.rows("SELECT COUNT(*) FROM customers, orders"), vec!["20"]);
    assert_eq!(
        d.rows("SELECT COUNT(*) FROM customers CROSS JOIN orders WHERE customers.id = orders.cust"),
        vec!["4"]
    );
    d.exec("CREATE TABLE ord2 (id INT PRIMARY KEY, note VARCHAR(5)); INSERT INTO ord2 VALUES (10,'x'),(12,'y')");
    assert_eq!(
        d.rows("SELECT orders.id, note FROM orders JOIN ord2 USING (id) ORDER BY 1"),
        vec!["10|x", "12|y"]
    );
    // three tables + composite primary key on the inner side
    assert_eq!(
        d.rows("SELECT c.name, i.sku, i.qty FROM customers c JOIN orders o ON o.cust = c.id JOIN items i ON i.order_id = o.id WHERE i.qty > 1 ORDER BY i.qty"),
        vec!["ann|a|2", "ann|a|5"]
    );
    // self join
    assert_eq!(
        d.rows("SELECT a.name, b.name FROM customers a JOIN customers b ON a.city = b.city AND a.id < b.id"),
        vec!["ann|cat"]
    );
    // t.* and *
    assert_eq!(
        d.rows(
            "SELECT o.*, c.name FROM orders o JOIN customers c ON c.id = o.cust WHERE o.id = 12"
        ),
        vec!["12|2|100.00|paid|bob"]
    );
    assert_eq!(
        d.q("SELECT * FROM customers c JOIN orders o ON o.cust = c.id")
            .columns
            .len(),
        7
    );
    // errors
    assert_eq!(
        d.err("SELECT id FROM customers c JOIN orders o ON o.cust = c.id"),
        1052
    );
    assert_eq!(
        d.err("SELECT x.id FROM customers c JOIN orders o ON o.cust = c.id"),
        1054
    );
    assert_eq!(
        d.err("SELECT 1 FROM customers c JOIN orders c ON 1 = 1"),
        1066
    );
    assert_eq!(d.err("SELECT 1 FROM customers c LEFT JOIN orders o"), 1064);
}

#[test]
fn aggregates_group_by_having() {
    let mut d = shop();
    assert_eq!(d.rows("SELECT COUNT(*), COUNT(total), SUM(total), AVG(total), MIN(total), MAX(total) FROM orders"), vec!["5|4|126.50|31.625000|1.00|100.00"]);
    assert_eq!(
        d.rows("SELECT COUNT(*), SUM(total), MAX(id) FROM orders WHERE id > 100"),
        vec!["0|NULL|NULL"]
    );
    assert_eq!(
        d.rows(
            "SELECT status, COUNT(*) AS n, SUM(total) FROM orders GROUP BY status ORDER BY status"
        ),
        vec!["open|2|5.50", "paid|3|121.00"]
    );
    assert_eq!(
        d.rows("SELECT cust, COUNT(*) n FROM orders GROUP BY cust HAVING n > 1"),
        vec!["1|2"]
    );
    assert_eq!(d.rows("SELECT cust FROM orders GROUP BY cust HAVING SUM(total) >= 25.5 ORDER BY SUM(total) DESC"), vec!["2", "1"]);
    assert_eq!(
        d.rows("SELECT COUNT(DISTINCT status), COUNT(DISTINCT cust) FROM orders"),
        vec!["2|4"]
    );
    assert_eq!(
        d.rows("SELECT GROUP_CONCAT(sku SEPARATOR '+') FROM items WHERE order_id = 10"),
        vec!["a+b"]
    );
    assert_eq!(d.rows("SELECT order_id % 2 AS parity, SUM(qty) FROM items GROUP BY order_id % 2 ORDER BY parity"), vec!["0|5", "1|5"]);
    // aggregates over a join
    assert_eq!(
        d.rows("SELECT c.city, COUNT(o.id), COALESCE(SUM(o.total), 0) FROM customers c LEFT JOIN orders o ON o.cust = c.id GROUP BY c.city ORDER BY c.city"),
        vec!["NULL|0|0", "paris|3|25.50", "rome|1|100.00"]
    );
    assert_eq!(
        d.rows("SELECT COUNT(*) + 1, MAX(id) - MIN(id) FROM orders"),
        vec!["6|4"]
    );
    assert_eq!(d.err("SELECT id FROM orders WHERE COUNT(*) > 1"), 1111);
    assert_eq!(d.err("SELECT SUM(COUNT(*)) FROM orders"), 1111);
    assert_eq!(d.rows("SELECT COUNT(*)"), vec!["1"]);
}

#[test]
fn subqueries_and_insert_select() {
    let mut d = shop();
    assert_eq!(d.rows("SELECT name FROM customers WHERE id IN (SELECT cust FROM orders WHERE status = 'paid') ORDER BY name"), vec!["ann", "bob"]);
    assert_eq!(
        d.rows(
            "SELECT name FROM customers WHERE id NOT IN (SELECT cust FROM orders) ORDER BY name"
        ),
        vec!["dan"]
    );
    assert_eq!(
        d.rows("SELECT name FROM customers WHERE id = (SELECT cust FROM orders WHERE id = 12)"),
        vec!["bob"]
    );
    assert_eq!(
        d.rows("SELECT (SELECT MAX(total) FROM orders) AS m"),
        vec!["100.00"]
    );
    assert_eq!(d.rows("SELECT EXISTS (SELECT 1 FROM orders WHERE total > 50), NOT EXISTS (SELECT 1 FROM orders WHERE total > 500)"), vec!["1|1"]);
    assert_eq!(
        d.rows("SELECT name FROM customers WHERE id IN (SELECT cust FROM orders WHERE id > 1000)"),
        Vec::<String>::new()
    );
    assert_eq!(
        d.err("SELECT name FROM customers WHERE id = (SELECT cust FROM orders)"),
        1242
    );
    assert_eq!(
        d.err("SELECT name FROM customers WHERE id IN (SELECT cust, id FROM orders)"),
        1241
    );
    assert_eq!(
        d.err(
            "SELECT name FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.cust = c.id)"
        ),
        1235
    );
    d.exec("UPDATE orders SET status = 'vip' WHERE cust IN (SELECT id FROM customers WHERE city = 'rome')");
    assert_eq!(
        d.rows("SELECT status FROM orders WHERE id = 12"),
        vec!["vip"]
    );
    d.exec("DELETE FROM items WHERE order_id NOT IN (SELECT id FROM orders WHERE cust < 99)");
    assert_eq!(d.rows("SELECT COUNT(*) FROM items"), vec!["4"]);
    d.exec("CREATE TABLE summary (cust INT PRIMARY KEY, n INT, total DECIMAL(10,2))");
    let r = d.q("INSERT INTO summary SELECT cust, COUNT(*), SUM(total) FROM orders GROUP BY cust");
    assert_eq!(r.affected, 4);
    assert_eq!(
        d.rows("SELECT * FROM summary ORDER BY cust"),
        vec!["1|2|25.50", "2|1|100.00", "3|1|NULL", "99|1|1.00"]
    );
    // INSERT … SELECT from the same table reads a stable snapshot.
    d.exec("CREATE TABLE twice (v INT); INSERT INTO twice VALUES (1),(2)");
    d.exec("INSERT INTO twice SELECT v + 10 FROM twice");
    assert_eq!(
        d.rows("SELECT v FROM twice ORDER BY v"),
        vec!["1", "2", "11", "12"]
    );
}

#[test]
fn interrupts() {
    let mut d = Db::new();
    d.exec("CREATE TABLE big (id INT PRIMARY KEY, v INT)");
    let values: Vec<String> = (0..600).map(|i| format!("({i},{})", i % 7)).collect();
    d.exec(&format!("INSERT INTO big VALUES {}", values.join(",")));
    let flag = Arc::new(AtomicBool::new(true));
    novadb_sql::set_cancel_flag(Some(flag.clone()));
    assert_eq!(d.err("SELECT COUNT(*) FROM big"), 1317);
    novadb_sql::set_cancel_flag(None);
    assert_eq!(d.rows("SELECT COUNT(*) FROM big"), vec!["600"]);
    d.exec("SET max_execution_time = 1");
    assert_eq!(
        d.err("SELECT COUNT(*) FROM big a JOIN big b ON a.v = b.v"),
        3024
    );
    d.exec("SET max_execution_time = 0");
    assert_eq!(
        d.rows("SELECT COUNT(*) FROM big a JOIN big b ON a.id = b.id"),
        vec!["600"]
    );
}

/// Joins against a brute-force nested loop over the same random data.
#[test]
fn joins_match_brute_force() {
    let mut d = Db::new();
    d.exec("CREATE TABLE a (id INT PRIMARY KEY, x INT, KEY kx (x)); CREATE TABLE b (id INT PRIMARY KEY, a_id INT, y INT, KEY ka (a_id))");
    let mut s: u64 = 0xDEAD_BEEF_1234_5678;
    let mut r = move |n: u64| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s % n
    };
    let mut av: Vec<(i64, Option<i64>)> = Vec::new();
    let mut bv: Vec<(i64, Option<i64>, i64)> = Vec::new();
    for i in 0..60 {
        let x = if r(6) == 0 { None } else { Some(r(8) as i64) };
        av.push((i, x));
    }
    for i in 0..150 {
        let a = if r(8) == 0 { None } else { Some(r(70) as i64) };
        bv.push((i, a, r(10) as i64));
    }
    let lit = |v: Option<i64>| v.map_or("NULL".to_string(), |v| v.to_string());
    d.exec(&format!(
        "INSERT INTO a VALUES {}",
        av.iter()
            .map(|(i, x)| format!("({i},{})", lit(*x)))
            .collect::<Vec<_>>()
            .join(",")
    ));
    d.exec(&format!(
        "INSERT INTO b VALUES {}",
        bv.iter()
            .map(|(i, a, y)| format!("({i},{},{y})", lit(*a)))
            .collect::<Vec<_>>()
            .join(",")
    ));
    for round in 0..120 {
        let left = r(2) == 0;
        let ylim = r(10) as i64;
        let xeq = r(8) as i64;
        let on_extra = r(3) == 0;
        let where_x = r(2) == 0;
        let sql = format!(
            "SELECT a.id, b.id FROM a {} JOIN b ON b.a_id = a.id{} {} ORDER BY a.id, b.id",
            if left { "LEFT" } else { "INNER" },
            if on_extra {
                format!(" AND b.y < {ylim}")
            } else {
                String::new()
            },
            if where_x {
                format!("WHERE a.x = {xeq}")
            } else {
                String::new()
            }
        );
        let mut want: Vec<String> = Vec::new();
        for (ai, ax) in &av {
            if where_x && *ax != Some(xeq) {
                continue;
            }
            let mut matched = false;
            for (bi, ba, by) in &bv {
                if *ba == Some(*ai) && (!on_extra || *by < ylim) {
                    want.push(format!("{ai}|{bi}"));
                    matched = true;
                }
            }
            if left && !matched {
                want.push(format!("{ai}|NULL"));
            }
        }
        assert_eq!(d.rows(&sql), want, "round {round}: {sql}");
        // grouped variant
        let gsql = format!(
            "SELECT a.id, COUNT(b.id) FROM a LEFT JOIN b ON b.a_id = a.id GROUP BY a.id HAVING COUNT(b.id) >= {} ORDER BY a.id",
            ylim % 4
        );
        let gwant: Vec<String> = av
            .iter()
            .map(|(ai, _)| (ai, bv.iter().filter(|(_, ba, _)| *ba == Some(*ai)).count()))
            .filter(|(_, n)| *n as i64 >= ylim % 4)
            .map(|(ai, n)| format!("{ai}|{n}"))
            .collect();
        assert_eq!(d.rows(&gsql), gwant, "round {round}: {gsql}");
    }
}
