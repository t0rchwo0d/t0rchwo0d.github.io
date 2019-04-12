---
title:  "Writeup - VolgaCTF 2019 Qualifier"
categories:
  - writeup
tags:
  - CTF
  - WEB
  - JAVA
---
# Web_Shop
## Description
There is an online shop. We can register, log in and make purchases. The goal is to buy the flag item, which costs $1337, but we have only a balance of $100.

## Obtain Source Code
**robots.txt**를 통하여 war 파일이 제공되는 것을 확인할 수 있다.
```shell
Disallow: /shop-1.0.0.war
```

## Analysis
소스코드를 살펴보면 상품을 구매하는 로직에서 전송되는 파라미터 조작을 통해 user Object에 원하는 값을 바인딩하여 user 원하는 object 업데이트가 가능하다. 이는 update() 메소드가 내부에 호출하기 때문에 가능하다.
```java
```

플래그를 획득하기 위해서는 기본 제공되는 돈이 100으로 설정되어 있으며 가진 돈을 조작하기 위해서는 balace를 조작한다. 그러나 아래와 같이 필터링이되어 있다.
```java
```

하지만 위 방식의 필터링은 대소문자를 구분하지 않으므로 Balnce와 같은 형태로 우회가 가능하여 balance 변수에 원하는 값을 바인딩할 수 있다.

## Payload
```shell
curl -X
```


# Web_Shop V2