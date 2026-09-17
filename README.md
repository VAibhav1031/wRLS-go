## wRLS_go

The project aims to Prove the use of the RLS (Row level Security) and how with it and without it we can solve the problem of the IDOR (Insecure direct Object Refrences). To have solution lets take the examnple having the endpoints (mostly query_parameter) with API like `example.com/?invoice_id=503` or `example.com/invoice/{invoice_id}`..

#### So What is the Problem Then ??
If we have application where user have ordered some product so to  see the invoice or redirected invoice of the order, At backend we  mostly have db tables like `user`, `product`, `order` (most common one's). If we fetch detail of the user from the order table then with this `/?invoice_id=505` , backend developer mostly use the `select * from orders where user_id=xyz invoice_id=999` and most often if you have forget the where user_id clause you leaked lots of user orders detail just like that ,even though we can say writing correct sql would protect it.

Will See how we can solve it with RLS And Withou RLS .

> RLS (Row Level Security , extra policy being attached to rows 

YUP !!, Right Queries would protect it without any problem , but.. 

#### The Catch (Why IDOR(Insecure direct object references) Still Happens):
- The risk isn't that a developer forgot their notes today—it's what happens six months from now:
- A new developer joins, writes a fast raw SQL patch under a tight deadline, and bypasses the central query repository.
- A complex endpoint gets refactored, and a nested WHERE condition gets lost inside a multi-table JOIN.
- An internal admin tool, microservice, or reporting script queries the database directly without passing through your main API's authorization checks.


so,

#### There is Three solution :

1. Naive one `Dont Write-Wrong Query` , This can be problematic in future.

2. Dont use the query_paramter in the url , use normal invoice_id mapping internaly where the invoice_id wont be public nor it is send through the  post request only /generate_invoice or /g_invoice at the end of th eendpoint , and internally we can solve this in backend by storing mapps for each invoice and invoice keys generated randomly and store there actual invoice_ids and  we use that  whenever request come and all 
(Pretty Extra for small stuff , but yeah good engineeering)

3. Using RLS the main thing we can use that which protect all of the above effor just with normal extra Security at the Database level.


---
>  This project experimental testing purpose, It's main only to show the use of the With RLS and Without RLS...

