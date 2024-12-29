#!/bin/bash

openssl ecparam -name prime256v1 -genkey -out tmcs-private.pem
openssl ec -in tmcs-private.pem -pubout -out tmcs-public.pem
