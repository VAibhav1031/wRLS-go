## wRLS_go

The project aims to prove the use of RLS (Row Level Security) and how, with it and without it, we can solve the problem of IDOR (Insecure Direct Object References). As a solution, let's take the example of having endpoints (mostly query parameters) with APIs like `example.com/?invoice_id=503` or `example.com/invoice/{invoice_id}`.

#### So What is the Problem Then?
If we have an application where a user has ordered some product, to see the invoice or redirected invoice of the order, at the backend we mostly have DB tables like `user`, `product`, `order` (the most common ones). If we fetch the details of the user from the order table, then with `/?invoice_id=505`, the backend developer mostly uses `select * from orders where user_id=xyz invoice_id=999`, and most often, if you forget the `where user_id` clause, you leak a lot of users' order details just like that — even though we can say writing the correct SQL would protect it.

We'll see how we can solve it with RLS and without RLS.

> RLS (Row Level Security), an extra policy being attached to rows

Yup, the right queries would protect it without any problem, but...

#### The Catch (Why IDOR (Insecure Direct Object References) Still Happens):
- The risk isn't that a developer forgot their notes today — it's what happens six months from now:
- A new developer joins, writes a fast raw SQL patch under a tight deadline, and bypasses the central query repository.
- A complex endpoint gets refactored, and a nested WHERE condition gets lost inside a multi-table JOIN.
- An internal admin tool, microservice, or reporting script queries the database directly without passing through your main API's authorization checks.

So,

#### There are three solutions:

1. The naive one: "Don't write the wrong query." This can be problematic in the future.

2. Don't use the query parameter with a public `invoice_id` in the URL; use a normal `invoice_id` shadowing design internally, or a UUID (something similar) where the `invoice_id` won't be public or unguessable, to prevent IDOR. Also, when accessed using `/invoice/{invoice_id}`, it can't be guessed to get another user's invoice. (Pretty extra for small stuff, but yeah, very important — also a good solution.)

3. Using RLS — the main thing we can use, which protects against all of the above just with an extra layer of security at the database level.

---
#### API created to showcase the whole situation, with RLS and without RLS

###### Endpoints & Other Info:

    1. /register - (Registering a new user in the user table, storing the password in hashed format using bcrypt with salt)
    2. /login - (Login, protected by incorrect-attempts blocking, JWT auth token)
    3. /checkout - (To create the order for the orders table)
    4. /checkoutRLS - (To create the order for the orders RLS table)
    5. /orders - (To get all orders from the normal orders table)
    6. /ordersRLS - (To get all the orders related to the orders RLS table, which is protected by Row Level Security — so we must use it)

Hostname: localhost [no public domain :), easily resolved]

Port: 9895

DB Used: PostgreSQL

---
#### Usage:
Below are the instructions related to setup and running.

##### Setup:
Use simple Docker Compose:
```bash
docker compose up
```

or just simply run

```bash
go run main.go # Start the Server...
```

and then just run the below command to have all the DB-level setup:

```bash
psql -U postgres -d postgres < ./initial_queries.sql
```
---

##### Use:

You can use curl CLI or Postman to test things — just add the necessary endpoints.

THESE ARE EXAMPLE CURL COMMANDS:

**Register**
```bash
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"desnake#45","email":"new@gmail.com","password":"hello="}' \
  http://localhost:9895/register
```

**Login**
```bash
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"desnake#45","password":"helloTL="}' \
  http://localhost:9895/login
```

**Checkout**
```bash
curl -v -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3OTAwNjg5ODAsInVzZXJfaWQiOjEwMH0.vkREx6wv5dhsJeijKL0uZXF7umjpWiTGF5fGWnaCQTE" \
  -d '{"items":[{"product_name":"pc","quantity":2,"price":1240.0}]}' \
  http://localhost:9895/checkout
```

that AUTH Token would be given after the successful login — you'll use that after `Bearer`.

**checkoutRLS**

Same as `checkout`, just change the endpoint.
```bash
curl -v -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3OTAwNjg5ODAsInVzZXJfaWQiOjEwMH0.vkREx6wv5dhsJeijKL0uZXF7umjpWiTGF5fGWnaCQTE" \
  -d '{"items":[{"product_name":"pc","quantity":2,"price":1240.0}]}' \
  http://localhost:9895/checkoutRLS
```

**orders**
```bash
curl -v -X GET \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3OTAwNjkxNDQsInVzZXJfaWQiOjEwMH0.VZ2GTa0ciDh9pX9Qo8LAMTfSg_5rlwBcI-vfQW83HYg" \
  http://localhost:9895/orders
```

**orderRLS**

Same as `orders`, just change the endpoint.
```bash
curl -v -X GET \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3OTAwNjkxNDQsInVzZXJfaWQiOjEwMH0.VZ2GTa0ciDh9pX9Qo8LAMTfSg_5rlwBcI-vfQW83HYg" \
  http://localhost:9895/ordersRLS
```

> **FEW IMPORTANT THINGS:**
>
> Make sure to provide all single orders in `[]` under the "items" key.

---

> This project is for experimental testing purposes; its main goal is only to show the use of RLS versus not using RLS.
