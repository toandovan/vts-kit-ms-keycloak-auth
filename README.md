Keycloak Auth Library for Spring Boot
-------
This library provides utilities that make it easy to integrate Keycloak into spring boot project

Feature List:
* [Feature](#feature)

Quick start
-------
* Just add the dependency to an existing Spring Boot project
```xml
<dependency>
    <groupId>com.atviettelsolutions</groupId>
    <artifactId>vts-kit-ms-keycloak-auth</artifactId>
    <version>1.0.0</version>
</dependency>
```

* Then, add the following properties to your `application-*.yml` file.
```yaml
vtskit:
  keycloak:
    realm: example
    auth-server-url: http://example:8080
    resource: example
    client-key-password: secret
```

Usage
-------
##### Feature
Login
```java
public AccessTokenResponse authenticate(UserDTO userDTO )
```
Logout
```java
public void logout(String refreshToken )
```
Get information of user
```java
public String getUserInfo( String token )
```
Refresh token
```java
public AccessTokenResponse refreshToken(String refreshToken )
```
Register User
```java
public AccessTokenResponse refreshToken(String refreshToken )
```
Build
-------
* Build with Unittest
```shell script
mvn clean install
```

* Build without Unittest
```shell script
mvn clean install -DskipTests
```

Contribute
-------
Please refer [Contributors Guide](CONTRIBUTING.md)

License
-------
This code is under the [MIT License](https://opensource.org/licenses/MIT).

See the [LICENSE](LICENSE) file for required notices and attributions.
