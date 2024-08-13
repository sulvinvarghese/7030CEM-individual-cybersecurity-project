const express = require('express');
const mysql = require('mysql');

const app = express();
const port = 3000;

const connection = mysql.createConnection({
  host: 'mysql',  // Docker service name
  user: 'root',
  password: 'password',
  database: 'testdb'
});

connection.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
});

app.get('/', (req, res) => {
  connection.query('SELECT NOW()', (err, results) => {
    if (err) {
      res.send('Error querying database');
      return;
    }
    res.send(`Current time: ${results[0]['NOW()']}`);
  });
});

app.listen(port, () => {
  console.log(`Node.js app listening at http://localhost:${port}`);
});