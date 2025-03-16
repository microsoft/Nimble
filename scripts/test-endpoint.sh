#!/bin/bash

tmcs=$1
handle=`dd if=/dev/urandom bs=16 count=1 | base64url`
tag0=`dd if=/dev/urandom bs=16 count=1 | base64url`
tag1=`dd if=/dev/urandom bs=16 count=1 | base64url`
nonce=`dd if=/dev/urandom bs=16 count=1 | base64url`

counter0="AAAAAAAAAAA="
counter1="AQAAAAAAAAA="

id_key=`curl --insecure $tmcs/serviceid?pkformat=der`
id=`echo $id_key | jq '.Identity' | sed -e 's/^"//' -e 's/"$//'`
public_key=`echo $id_key | jq '.PublicKey' | sed -e 's/^"//' -e 's/"$//'`
echo -e "$public_key"==== | fold -w 4 | sed '$ d' | tr -d '\n' | base64url --decode > public.der
openssl ec -pubin -inform der -in public.der -outform pem -out public.pem

sig=`curl --header "Content-Type: application/json" --request PUT --data "{\"Tag\":\"$tag0\"}" --insecure $tmcs/counters/$handle?sigformat=der`
create_counter_sig=`echo $sig | jq '.Signature' | sed -e 's/^"//' -e 's/"$//'`
echo -e "$create_counter_sig"==== | fold -w 4 | sed '$ d' | tr -d '\n' | base64url --decode > create-counter-sig.bin
echo -n "$id.$handle.$counter0.$tag0" | sed -e 's/=//g' > create-counter-msg.txt
openssl dgst -sha256 -verify public.pem -signature create-counter-sig.bin create-counter-msg.txt

sig=`curl --header "Content-Type: application/json" --request POST --data "{\"Tag\":\"$tag1\",\"ExpectedCounter\":1}" --insecure $tmcs/counters/$handle?sigformat=der`
increment_counter_sig=`echo $sig | jq '.Signature' | sed -e 's/^"//' -e 's/"$//'`
echo -e "$increment_counter_sig"==== | fold -w 4 | sed '$ d' | tr -d '\n' | base64url --decode > increment-counter-sig.bin
echo -n "$id.$handle.$counter1.$tag1" | sed -e 's/=//g' > increment-counter-msg.txt
openssl dgst -sha256 -verify public.pem -signature increment-counter-sig.bin increment-counter-msg.txt

resp=`curl --insecure $tmcs/counters/$handle?nonce=$nonce\&sigformat=der`
read_counter_sig=`echo $resp | jq '.Signature' | sed -e 's/^"//' -e 's/"$//'`
echo -e "$read_counter_sig"==== | fold -w 4 | sed '$ d' | tr -d '\n' | base64url --decode > read-counter-sig.bin
echo -n "$id.$handle.$counter1.$tag1.$nonce" | sed -e 's/=//g' > read-counter-msg.txt
openssl dgst -sha256 -verify public.pem -signature read-counter-sig.bin read-counter-msg.txt

