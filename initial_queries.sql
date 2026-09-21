CREATE DATABASE wrls;
\c wrls

CREATE SCHEMA IF NOT EXISTS experiment; --create the new_schema
SET client_encoding = 'UTF8';
SET search_path = experiment, public;


-- create the Table users
CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY START WITH 100, 
    username varchar(30) UNIQUE NOT NULL,
    email varchar(30) NOT NULL,
    hashed_password varchar(255)  NOT NULL

);

-- table orders 
CREATE TABLE IF NOT EXISTS orders (
    order_id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    public_invoice_id UUID NOT NULL,
    product_name varchar(50) NOT NULL, 
    price numeric(10,2) NOT NULL, 
    quantity numeric NOT NULL

);

-- table orders_rls which will have the RLS (Row Level Security)
CREATE TABLE IF NOT EXISTS orders_rls (
    order_id INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    invoice_id INT UNIQUE NOT NULL,
    product_name VARCHAR(50) NOT NULL,
    price NUMERIC(10,2) NOT NULL,
    quantity NUMERIC NOT NULL
);



CREATE SEQUENCE IF NOT EXISTS invoice_id_seq START WITH 1000


-- Create the application role , does we use this application role for the user, login also  or only for the orders_rls 
CREATE ROLE app_user LOGIN PASSWORD 'something_secret';

-- Allow the aTcess to the db wrls whenever we connect using login as the app_user
GRANT CONNECT ON DATABASE wrls TO app_user;



--ALL GRANTS ::
-- Also Grant the  acess to schema usage , if not then nothing will be visible
--
GRANT USAGE ON schema experiment to app_user;

-- GRANT the acess to the users for the login, register usages ..  
GRANT SELECT, INSERT, UPDATE ON users TO app_user;

-- CRUD  Access 
GRANT SELECT, INSERT, UPDATE, DELETE ON  orders, orders_rls TO app_user;

-- Sequence permissions (Required for auto-incrementing identity IDs)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA experiment TO app_user;

--
GRANT USAGE, SELECT ON SEQUENCE invoice_id_seq TO app_user;

-- 
--


--  ALTERING...
-- Made the search path for the particular role to be this ..
ALTER ROLE app_user SET search_path TO experiment, public;

-- Initiate the RLS only on orders_rls,   
ALTER TABLE orders_rls ENABLE ROW LEVEL SECURITY;


CREATE POLICY orders_rls_policy on orders_rls FOR ALL  TO app_user 
USING(
   
    user_id = NULLIF(current_setting('app.currrent_user_id',true),'')::INT
    AND
    (
        NULLIF(current_setting('app.current_invoice_id',true),'') IS NULL
        or invoice_id = NULLIF(current_setting('app.current_invoice_id',true), '')::INT    
)
WITH CHECK (
    invoice_id = NULLIF(current_setting('app.current_invoice_id',true), '')::INT
);

-- Restrictive Maintenance Mode Emergency Brake
CREATE POLICY enforce_maintenance_policy ON orders_rls 
AS RESTRICTIVE 
FOR ALL 
TO app_user
USING (
    current_setting('app.maintenance_mode', true) IS DISTINCT FROM 'on'
);



