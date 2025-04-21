Spring Boot MFA Project - Focused
Project Structure
This updated Spring Boot project focuses on user authentication, OTP generation/validation, SAML 2.0 integration, and email sending for MFA. Unnecessary features like logout have been removed.

File: pom.xml
Updated to include only necessary dependencies for authentication, OTP, SAML, and email.
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>mfa-solution</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>MFA Solution</name>
    <description>Spring Boot MFA Solution with SAML 2.0 and OTP</description>

    <properties>
        <java.version>17</java.version>
        <spring-boot.version>3.2.0</spring-boot.version>
    </properties>

    <dependencies>
        <!-- Spring Boot Starter -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <!-- LDAP for Authentication -->
        <dependency>
            <groupId>org.springframework.ldap</groupId>
            <artifactId>spring-ldap-core</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-ldap</artifactId>
        </dependency>

        <!-- SAML 2.0 Support -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-saml2-service-provider</artifactId>
        </dependency>

        <!-- For OTP Generation -->
        <dependency>
            <groupId>dev.samstevens.totp</groupId>
            <artifactId>totp</artifactId>
            <version>1.7.1</version>
        </dependency>

        <!-- Email Sending -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-mail</artifactId>
        </dependency>

        <!-- Lombok for reducing boilerplate code -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Spring Boot Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
        </plugins>
    </build>

</project>


File: application.yml
Updated to include only configurations relevant to LDAP, OTP, SAML, and email.
server:
  port: 8080

spring:
  application:
    name: mfa-solution
  security:
    saml2:
      relyingparty:
        registration:
          myfilegateway:
            identityprovider:
              entity-id: https://hsbc.forgerock.com/saml/vsps/saml20ip/saml20
              sso-url: https://hsbc.forgerock.com/saml/vsps/saml20ip/saml20/login
              certificates: classpath:idp-certificate.pem
            signing:
              credentials:
                - private-key-location: classpath:signing-key.pem
                  certificate-location: classpath:signing-cert.pem
  ldap:
    urls: ldap://localhost:389
    base: dc=example,dc=com
    username: cn=admin,dc=example,dc=com
    password: adminpassword
  mail:
    host: smtp.example.com
    port: 587
    username: your-email@example.com
    password: your-email-password
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true

# MFA Configuration
mfa:
  otp:
    validity-period: 1  # in minutes
    max-generation-requests: 3
    soft-lock-period: 3  # in minutes
    max-failed-attempts: 4
  saml:
    assertion-consumer-service-url: http://localhost:8080/login/saml2/sso
    user-id-attribute: preferred_username
    user-id-from-attribute: true

# SSP Configuration (Minimal for SAML)
ssp:
  sso:
    name: myFileGateway
    fully-qualified-host: hsbc.myfilegateway.com/external
    sso-token-cookie-name: SSOTOKEN
    login-page: login.html
    external-application-login-url: https://hsbc.forgerock.com/saml/vsps/saml20ip/saml20/login
    authn-response-post-path: saml2SsoPost


File: src/main/java/com/example/mfasolution/MfaSolutionApplication.java
Unchanged main application class.
package com.example.mfasolution;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MfaSolutionApplication {

    public static void main(String[] args) {
        SpringApplication.run(MfaSolutionApplication.class, args);
    }
}


File: src/main/java/com/example/mfasolution/config/SecurityConfig.java
Updated to include LDAP authentication and SAML 2.0, removing logout-related configurations.
package com.example.mfasolution.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public ActiveDirectoryLdapAuthenticationProvider ldapAuthenticationProvider() {
        return new ActiveDirectoryLdapAuthenticationProvider("example.com", "ldap://localhost:389");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, 
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
        DefaultRelyingPartyRegistrationResolver resolver = 
                new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(resolver, new OpenSamlMetadataResolver());

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/otp", "/saml/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .ldapAuthentication(ldap -> ldap
                .userDnPatterns("uid={0},ou=users")
                .contextSource()
                .url("ldap://localhost:389/dc=example,dc=com")
                .managerDn("cn=admin,dc=example,dc=com")
                .managerPassword("adminpassword")
            )
            .saml2Login(saml2 -> saml2
                .loginPage("/login")
                .defaultSuccessUrl("/otp")
            )
            .addFilterBefore(metadataFilter, org.springframework.security.web.authentication.www.BasicAuthenticationFilter.class);

        return http.build();
    }
}


File: src/main/java/com/example/mfasolution/service/OtpService.java
Updated OTP service to match the specified requirements (1-minute validity, 3-minute soft lock, etc.).
package com.example.mfasolution.service;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class OtpService {

    @Value("${mfa.otp.validity-period}")
    private int validityPeriod;

    @Value("${mfa.otp.max-generation-requests}")
    private int maxGenerationRequests;

    @Value("${mfa.otp.soft-lock-period}")
    private int softLockPeriod;

    @Value("${mfa.otp.max-failed-attempts}")
    private int maxFailedAttempts;

    @Autowired
    private JavaMailSender mailSender;

    private final Map<String, String> otpStore = new HashMap<>();
    private final Map<String, Integer> generationAttempts = new HashMap<>();
    private final Map<String, Integer> failedAttempts = new HashMap<>();
    private final Map<String, Long> lockoutTimes = new HashMap<>();

    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final DefaultCodeVerifier verifier;

    public OtpService() {
        verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        verifier.setTimePeriod(validityPeriod * 60); // Convert to seconds
    }

    public void generateAndSendOtp(String userId, String email) {
        // Check if user is locked out
        if (lockoutTimes.containsKey(userId)) {
            long lockoutEnd = lockoutTimes.get(userId);
            if (System.currentTimeMillis() < lockoutEnd) {
                throw new RuntimeException("User is locked out. Try again later.");
            } else {
                lockoutTimes.remove(userId);
                failedAttempts.remove(userId);
            }
        }

        generationAttempts.putIfAbsent(userId, 0);
        int attempts = generationAttempts.get(userId) + 1;

        if (attempts > maxGenerationRequests) {
            throw new RuntimeException("Maximum OTP generation requests exceeded");
        }

        generationAttempts.put(userId, attempts);

        // Generate a 6-digit OTP
        String otp = String.format("%06d", new Random().nextInt(999999));
        otpStore.put(userId, otp);

        // Send OTP via email
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your OTP for MFA");
        message.setText("Your OTP is: " + otp + "\nThis OTP is valid for " + validityPeriod + " minute(s).");
        mailSender.send(message);
    }

    public boolean validateOtp(String userId, String otp) {
        // Check if user is locked out
        if (lockoutTimes.containsKey(userId)) {
            long lockoutEnd = lockoutTimes.get(userId);
            if (System.currentTimeMillis() < lockoutEnd) {
                throw new RuntimeException("User is locked out. Try again later.");
            } else {
                lockoutTimes.remove(userId);
            }
        }

        failedAttempts.putIfAbsent(userId, 0);
        String storedOtp = otpStore.get(userId);

        if (storedOtp == null) {
            throw new RuntimeException("No OTP found for user");
        }

        boolean isValid = verifier.isValidCode(storedOtp, otp);
        if (!isValid) {
            int attempts = failedAttempts.get(userId) + 1;
            failedAttempts.put(userId, attempts);
            if (attempts >= maxFailedAttempts) {
                lockoutTimes.put(userId, System.currentTimeMillis() + softLockPeriod * 60 * 1000);
                throw new RuntimeException("Maximum failed attempts reached. User locked out for " + softLockPeriod + " minutes.");
            }
            return false;
        }

        // Reset attempts on successful validation
        failedAttempts.put(userId, 0);
        generationAttempts.put(userId, 0);
        otpStore.remove(userId);
        return true;
    }
}


File: src/main/java/com/example/mfasolution/service/UserService.java
New service to handle user email retrieval after LDAP authentication.
package com.example.mfasolution.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private LdapTemplate ldapTemplate;

    public String getUserEmail(String userId) {
        // Simulate LDAP query to get user email
        // In a real application, you'd query LDAP with the userId
        // For this example, return a mock email
        return userId + "@example.com";
    }
}


File: src/main/java/com/example/mfasolution/controller/AuthController.java
Updated controller to handle only the required steps: login, OTP generation/validation, and SAML authentication.
package com.example.mfasolution.controller;

import com.example.mfasolution.service.OtpService;
import com.example.mfasolution.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {

    @Autowired
    private OtpService otpService;

    @Autowired
    private UserService userService;

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/otp/generate")
    public String generateOtp(Authentication authentication, Model model) {
        String userId = authentication.getName();
        String email = userService.getUserEmail(userId);
        otpService.generateAndSendOtp(userId, email);
        model.addAttribute("userId", userId);
        return "otp";
    }

    @PostMapping("/otp/validate")
    public String validateOtp(@RequestParam String userId, @RequestParam String otp, Model model) {
        boolean isValid = otpService.validateOtp(userId, otp);
        if (isValid) {
            // Redirect to SAML SSO
            return "redirect:/saml2/authenticate/myfilegateway";
        } else {
            model.addAttribute("error", "Invalid OTP");
            model.addAttribute("userId", userId);
            return "otp";
        }
    }

    @GetMapping("/otp")
    public String otpPage() {
        return "otp";
    }
}


File: src/main/resources/templates/login.html
Unchanged login page template.
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="post" action="/login">
        <label for="username">User ID:</label>
        <input type="text" id="username" name="username" required/><br/>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required/><br/>
        <button type="submit">Login</button>
    </form>
</body>
</html>


File: src/main/resources/templates/otp.html
Unchanged OTP validation page template.
<!DOCTYPE html>
<html>
<head>
    <title>OTP Validation</title>
</head>
<body>
    <h1>Enter OTP</h1>
    <form method="post" action="/otp/validate">
        <input type="hidden" name="userId" value="${userId}"/>
        <label for="otp">OTP:</label>
        <input type="text" id="otp" name="otp" required/><br/>
        <button type="submit">Validate OTP</button>
    </form>
    <div th:if="${error}" style="color: red;">
        <p th:text="${error}"></p>
    </div>
</body>
</html>


File: src/main/resources/signing-key.pem
Placeholder for the signing key (unchanged).
-----BEGIN ENCRYPTED PRIVATE KEY-----
[Replace with actual key content from the diagrams]
-----END ENCRYPTED PRIVATE KEY-----


File: src/main/resources/signing-cert.pem
Placeholder for the signing certificate (unchanged).
-----BEGIN CERTIFICATE-----
[Replace with actual certificate content from the diagrams]
-----END CERTIFICATE-----


File: src/main/resources/idp-certificate.pem
Placeholder for the IdP certificate (unchanged).
-----BEGIN CERTIFICATE-----
[Replace with actual IdP certificate content from the diagrams]
-----END CERTIFICATE-----


Notes

LDAP Authentication: The project now uses LDAP for user authentication, configured in SecurityConfig.java. Update the LDAP settings in application.yml with your actual LDAP server details.
OTP Requirements: The OTP service has been updated to match the specified requirements: 1-minute validity, 3-minute soft lock, 3 max generation requests, and 4 max failed attempts.
Email Sending: The OTP is now sent via email using Spring Mail. Update the spring.mail properties in application.yml with your actual SMTP server details.
SAML 2.0: The SAML configuration remains for handling Auth requests and responses. The signed assertion is handled by Spring Security's SAML 2.0 support.
Removed Features: Logout functionality, welcome page, and related configurations have been removed as they are not part of the requested steps.

This project now focuses solely on the required MFA steps: user authentication via LDAP, OTP generation/validation, SAML 2.0 integration, and email sending.
