Introduction
In this activity,  generate secure code for a web application, focusing on mitigating common vulnerabilities such as SQL injection and cross-site scripting (XSS). You’ll also write tests to ensure the generated code protects against potential security threats.

This is the first of three activities in which you’ll secure the SafeVault application. The secure coding practices implemented here will serve as the foundation for authentication and authorization systems in subsequent activities.

Instructions
Step 1: Review the scenario
To begin, review the following scenario related to building the "SafeVault" web application:

SafeVault is a secure web application designed to manage sensitive data, including user credentials and financial records. As the lead developer, your role is to ensure the application is robust against attacks by implementing secure coding practices.

The initial requirements include:

Validating user inputs to prevent malicious injections.

Securing database queries to eliminate SQL injection vulnerabilities.

Testing the code to ensure it resists XSS and SQL injection attacks.

Your goal is to use write secure code and generate tests that simulate attack scenarios.

Here is the base code for the application:

Web Form (Input Validation)


<!-- webform.html -->
<form action="/submit" method="post">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username">
    
    <label for="email">Email:</label>
    <input type="email" id="email" name="email">
    
    <button type="submit">Submit</button>
</form>
Database Schema and Connection (Parameterized Queries)

-- database.sql
CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100),
    Email VARCHAR(100)
);
Test Framework Setup (Testing for Vulnerabilities)

// Tests/TestInputValidation.cs
using NUnit.Framework;
[TestFixture]
public class TestInputValidation {
    [Test]
    public void TestForSQLInjection() {
        // Placeholder for SQL Injection test
    }
    [Test]
    public void TestForXSS() {

Step 2: Generate secure code for input validation
generate code that:

Validates user inputs by removing malicious characters and ensuring data integrity.

Prevents users from entering potentially harmful scripts or queries.

Example: Implement a function that sanitizes inputs in a web form, such as username and email.

Step 3: Use parameterized queries to prevent SQL injection

Write database queries using parameterized statements.

Securely handle user-provided data, such as login credentials or search inputs.

Example: Generate a secure query to retrieve user information by using placeholders for parameters.

Step 4: Test the code for vulnerabilities

Generate unit tests to simulate SQL injection attempts.

Write tests for XSS vulnerabilities by injecting malicious scripts into user inputs.

Run the tests and verify that the generated code effectively prevents these attacks.

Step 5: Save your work
By the end of this activity, you will have:

Secure code that validates user inputs and prevents SQL injection attacks.

Tests that verify the robustness of the code against common vulnerabilities.

Save all secure code and test cases in your sandbox environment. 