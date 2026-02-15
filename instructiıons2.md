In this activity, you’ll secure the SafeVault application by implementing authentication and authorization mechanisms. Authentication ensures that only legitimate users can access the system, while authorization restricts access to specific features based on user roles. you’ll generate and test code to establish these essential security layers. 

This is the second of three activities. The secure coding practices and base code implemented in Activity 1 will serve as the foundation for protecting user accounts in this activity.

Instructions
Step 1: Review the scenario
SafeVault needs robust access control mechanisms to prevent unauthorized access to sensitive data. The system should:

Verify user credentials during login (authentication).

Restrict access to certain features, such as administrative tools, based on user roles (authorization).

Your goal is to  generate code for these functionalities and test them for reliability.

Step 2: Generate authentication code

Write code for user login functionality, including verifying usernames and passwords.

Hash passwords securely using a library like bcrypt or Argon2.

Example: Implement a function to authenticate users by comparing hashed passwords.

Step 3: Implement role-based authorization (RBAC)
generate code that:

Assigns roles to users (e.g., admin, user).

Restricts access to specific routes or features based on roles.

Example: Protect the Admin Dashboard so only users with the admin role can access it.

Step 4: Test the authentication and authorization system

Write test cases to simulate scenarios like invalid login attempts and unauthorized access.

Test access control for users with different roles.

Step 5: Save your work
By the end of this activity, you will have:

A working authentication and authorization system for SafeVault.

Tests verifying proper access control for different user roles.

