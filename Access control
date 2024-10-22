# **Access control**

## **Unprotected admin functionality**

view `robots.txt` ⇒ admin 

## **Unprotected admin functionality with unpredictable URL**

admin panel discloses in JavaScript 

## **User role controlled by request parameter**

/admin ⇒ cookie `Admin=false`. Change it to `Admin=true`

## **User role can be modified in user profile**

response shows your `roleid` has changed to other

## **User ID controlled by request parameter**

URL contains your username in the "id" parameter.  ex:  id=ahmed

## **User ID controlled by request parameter, with unpredictable user IDs**

the post or comment of zeyad has her id take him  and use to login

## **User ID controlled by request parameter with data leakage in redirect**

the post or comment of zeyad has her id take him  and use to login

but u back to home or other page with sensitive data like APIKEY

## **User ID controlled by request parameter with password disclosure**

1. Change the "id" parameter in the URL to `administrator`.
2. View the response in Burp and observe that it contains the administrator's password

## **Insecure direct object references**

Change the filename From `2.txt` to `1.txt` and download is contenues

## **URL-based access control can be circumvented**

framework that supports the `X-Original-URL` header
1. Send the request to Burp Repeater. Change the URL in the request line to `/` and add the HTTP header `X-Original-URL: /invalid`. Observe that the application returns a "not found" response. This indicates that the back-end system is processing the URL from the `X-Original-URL` header.

## **Method-based access control can be circumvented**

have 2 acount can send requste admin from normal user by change method

## **Multi-step process with no access control on one step**

have 2 acount can send requste admin from normal user by use cookie of user  

## **Referer-based access control**

have 2 acount can send requste admin from normal user by use cookie of user  and delete **Referer**
