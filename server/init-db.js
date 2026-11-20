require('dotenv').config();
const fs=require('fs'); const {Pool}=require('pg');
(async()=>{const pool=new Pool({connectionString:process.env.DATABASE_URL});try{await pool.query(fs.readFileSync('db/schema.sql','utf8'));console.log('Database schema installed.');}catch(e){console.error(e.message);process.exitCode=1;}finally{await pool.end();}})();
