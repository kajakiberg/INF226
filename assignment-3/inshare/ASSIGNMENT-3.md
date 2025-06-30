# Mandatory Assignment 3 – INF226 – 2024

Welcome to the third and final mandatory assignment of INF226 (Software Security). In this assignment, you will be improving the security of a program called InShare—a note-sharing web application that has been deliberately crafted to include a number of security flaws. As you discovered in the previous assignment, InShare suffers from vulnerabilities that compromise its security.

Your task is to analyze these vulnerabilities, plan improvements, and ultimately secure the application. You will be working in phases, focusing on design, implementation and review.

From the learning outcomes of the course:

 - "The student masters, theoretically and practically, programming techniques to develop
secure, safe, reliable, and robust systems, and can assess the security of given source code or application."
 - "The student can plan and carry out varied assignments and projects for secure software, can develop critical thinking about secure software, can exchange opinions with other professionals and participate in developing best practices for secure software."


## Group Work

This project is to be carried out by groups of 1–3 students. You may choose to retain your previous group from earlier assignments, or you can form a new group. Make sure that everyone is signed up for the group on MittUiB. **Note:** This assignment includes a bit more programming than the previous assignments, so even if you worked alone on the previous assignments, you may consider forming a group for this one. Even if you prefer to work alone, you are strongly
 encouraged to find another which can review your code.

We encourage collaboration through GitLab for branching, merge requests, and peer review. Each member of the group is expected to contribute to both the analysis and implementation of the security improvements.

# Phases and Iteration

The assignment is divided into three phases: Planning, Implementation and Review. These phases are not disjoint, and you should expect a feedback loop where planning, implementation, testing and review may cycle multiple times.

You will be working on each phase simultaneously, addressing different areas of security (e.g., authentication, SQL injection, access control, CSRF, XSS) at various stages of completion. This mirrors real-world software development processes, where issues are identified, planned for, fixed, and reviewed iteratively.

## Forking the Project on GitLab

To get started, you will first need to fork the InShare project on GitLab. Visit the project repository on the [UiB GitLab instance](https://git.app.uib.no) and click on the "Fork" button to create your own copy of the project. Once your fork is created, make sure to set the repository to private under the project settings.

You must also give access to the TAs and the lecturer. To do this, go to the "Manage" → "Members" section of your repository and add the teachers as developers:

 - Håkon Gylterud
 - Willem Schooltink
 - Shania Muganga
 - Jonas Haukenes
 - Julie Mikkelsen
 - Endre Sletnes
 - Eivind Sulen

GitLab will be your main platform for collaboration, where you can create branches for working on different parts of the code, open issues to document vulnerabilities, and create merge requests for peer review. Ensure that all members of your group actively contribute by using branches and reviewing each other’s work.

**Remember to add any libraries you want to use to the pom.xml file.**

## Documenting your work

**Fill out the report in the bottom of this page as you go along.** It is divided into sections already with some suggestions what to write.

## Phase 1: Planning mitigations

In the first phase you should plan how to improve the security of InShare. **Write down your planning in the report in the bottom of this page.**


### SQL injection

Plan the mitigation of SQL injection, and create GitLab issues for the fixes. How will you determine/test that the vulnerability is fixed?


### XSS

Plan the mitigation of existing XSS vulnerabilities. The cruicial part to consider is the content of notes.
The solution for text formatting *requires* use of HTML tags in the content of notes.
One possible solution would be to use an HTML Sanitiser (such as [OWASP AntiSamy](https://owasp.org/www-project-antisamy/)).

How will you determine that the vulnerability is fixed?

Create a mitigation plan and GitLab issues for the fixes.

### CSRF

Plan the mitigation of CSRF vulnerabilities in InShare, and create GitLab issues for the fixes.

How will you determine that the vulnerability is fixed?

### Authentication

In the previous assignment we identified weaknesses in the authentication system of InShare.
In particular there is no key derivation function applied to the password before storing it in the database,
and there are no requirements on password lengths.

Focussing on password storage using a key derivation function (Argon2 or scrypt are recommended)
and ensuring user password strength, create a plan
for improving the authentication system in InShare. Break the plan into GitLab issues.

Some things to consider:

 - Will there be any changes to the UI?
 - What are best practises to encourage users to pick a strong password?
 - How will you determine that the security of the authentication mechanism is improved?

### Access control

The problems with access control in InShare is twopart:

 - Insufficient checks on permissions: Most permissions are only enforced in the UI. Only the
   DELETE permission is checked in the backend.
 - Limited access control model: The access control list method is probably not the best
   fit for the application.

It will be practical to address the second issue first by replacing the access control system,
and then the second one by ensuring that the new access control system verifies all permissions
in the backend.

Plan for the creation of a Role Based Access Control (RBAC) for InShare:

 - Include a new database schema for the roles and permissions. Remember to set up foreign keys, and add additional constraints where suitable.
 - The roles should be:
   - "owner": Each note has a unique owner. Has read/write/delete permissions. Cannot be revoked, only transferred by the owner themselves.
   - "administrator": Has read/write/delete permissions. Can set roles (except owner).
   - "editor": Has read/write permissions.
   - "reader": Can only read the note.
 - Plan which methods on the backend have to include checks for permssions, and how this will be coordinated with the UI.
 - Change the UI so that the sharing mechanism uses the new roles. Include an option to transfer ownership of a note.
 - How will you determine that the security of the access control mechanism has improved?

### Logging

There is currently very little logging going on in InShare. Identify what logging is taking place, and plan the introduction
of more security logging. Make sure that you follow best practises on what to log and what not to log.

Create GitLab issues for adding logging to various parts of the code.

## Phase 2: Implementation

In this phase you will do the actual implementation of the fixes. Make the fixes on separate branches, and follow
the issues you have created. In the report you can mention any particular challenges you had to overcome in the
implementation.

### Impelment protections against SQL injection, XSS, CSRF

Working in separate branches, implement the fixes for SQL injection, XSS and CSRF, according to your plan from the
previous phase. Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.

### Implement improvements to authentication

Working in a seprarate branch, implement the authentication changes planned in phase 1.
Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.

### Implement improvements to access control

Working in a seprarate branch, implement the access control changes planned in phase 1.
Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.

### Implement logging improvements

Working in a seprarate branch, follow the previous laid out plan to implement security logging.
Do not merge into the main branch until another team member has peer-reviewed your code. See next phase.


## Phase 3: Review and testing

**Note**: Even if you are working alone, get someone else from the course to review your code if at all possible.

In this phase you submit a merge request for each of the branches from the previous phase, and peer-review the changes.

 - Remember to test your code before submitting a merge request.
 - Be clear in the merge request what is being implemented, and which issues are affected.

When reviewing think about the following:

 - Focus on security.
 - Check that the code is readable and is clear.
 - Test the code. Checkout the branch and do some manual testing.
 - Be constructive in your feedback! Start by saying something postitive.
 - Verify that the changes addresses the correct issues.

When you are done, make sure that correct issues are closed.


# Report

Here you can document your work.


## SQL Injection Protection (2 pts)

There is a SQL injection vulnerability in the User.loadReadableNotes method. User input (username) is directly concatenated into the SQL query. This allows for SQL injection because the entire query string, including user-provided input, is interpreted as SQL code. 

Usernames containing special characters, such as single quotes or SQL keywords, are stored without validation. This allows a malicious user to submit SQL code within the username field during registration. When used in later database queries, this unvalidated username could inject SQL commands, leading to SQL injection vulnerabilities during login or other operations that use username in queries.

### Planning

The plan is to replace SQL queries with parameterized placeholders (?). This way user input will be treated as data, not as part of the SQL query itself.

To mitigate the issue regarding special characters in usernames, validation of user input will be implemented. This will prohibit the creation of users with usernames containing special characters of SQL metacharacters, that are potentially dangerous.

Classes to modify:
RegistrationContoller.java
User.java

Plan for testing:
Test SQL injection attacks from Mandatory Assignment 2 (MA2). 

Link to issue(s) created.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/issues/2

### Implementation

There was some confusion around which load-method in User, contained the vulnerability. An attempt to modify the User.load() method was commited. However, these changes were simply reverted before this fix:

https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/1/diffs?commit_id=74f59324846e390986078103ec4b9a975f46621c

In this commit, I attempted to use a seperate ValidationUtils class for username validation, but this seemed unnecessary and was also removed in the final fix: 
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/1/diffs?commit_id=9338f9033c88867bcc2b9b7ec9554f4da9d8d10f


### Review

After updating User.loadReadableNotes with parameterized placeholders, the SQL injection scripts from MA2 2.1.b and 2.1.c were run. In MA2, both scripts were successful in verifying the sql vulnerability and performing the sql injection attack. This time, none of the payloads were successful in either verifying a sql vulnerability or performing a sql injection attack. This indicated that the specific vulnerability located is mitigated.

After user input validation was introduced to RegistrationController.register(), users cannot be created with usernames containing special characters. In MA2, one of the strategies to gain unauthorized access to notes, was registering as a user with an SQL injection payload as the username. Testing this approach using the same, and other similar, usernames as in MA2, “test' OR '1'='1”, are no longer be accepted. 

Link to merge request with review.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/1

## XSS Protection (3 pts)

Several instances in Thymeleaf templates use th:text and th:utext attributes to directly inject data from the server into HTML. th:utext in particular directly inserts unescaped HTML, which is vulnerable to XSS if the data is not sanitized.


### Planning

From MA2, I have only found ways to perform XSS attacks to different /note endpoints, and will therefore focus on mitigation in the NoteController and Note classes. The plan is to sanitize data on the server side, before it is passed to the templates. Jsoup library will be used to clean user inputs before saving or displaying them.

Sanitizations need to be implemented in the following classes:
-	NoteController
-	User
-	Note
-	RegistrationController

Link to issue(s) created.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/issues/3

### Implementation

My initial commit used sanitization with jsoup.safety's Safelist.basic().
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/2/diffs?commit_id=211c92790f2fb17798823e2f596eadd367f02aea

This caused formatting issues with using styles such as 'Huge', 'Large' and 'Small' in the note editor. Therefore, essential tags and attributes were added to the safelist, to allow formatting. I committed several times after this fix, because of some issues with pushing. See merge request for final fix.

### Review

The XSS attack from MA2 was not successful after adding sanitization to the NoteController and Note classes. The approach was to send POST requests from the developer tool console, using different HTML tags like img, div, svg etc.

I also tried simulating POST requests from the terminal with curl, also with different HTML tags, and none of the attempts were successful.

Formatting functionality in the note editor was tested and working after the final fix.

Link to merge request with review.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/2?commit_id=211c92790f2fb17798823e2f596eadd367f02aea

## CSRF Protection (2 pts)

CSRF tokens are explicitly disabled in SecurityConfig, leading to CSRF vulnerabilities. The NoteController.deleteNote method is especially vulnerable with its use of @GetMapping. @GetMapping is intended for retrieving data and should be safe and idempotent. Using @GetMapping for actions like deleting a note exposes the application to CSRF risks because anyone can make a GET request to trigger a delete action if the user is authenticated. This is a vulnerability even with CSRF tokens enabled, because GET requests are typically allowed without CSRF tokens.

### Planning

The plan for mitigating CSRF vulnerabilities is:
-	Enable CSRF tokens
-	Replace @GetMapping in NoteController.deleteNote method


https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/issues/4

### Implementation
After merging into main branch, an issue appeared with submitting the register form. This was solved by replacing line 25 in SecurityConfig.java with .csrf(csrf -> csrf.ignoringRequestMatchers("/register")). Removing CSRF protection specifically for /register solved the problem by ensuring that the registration request was not blocked, as this endpoint must be accessible without authentication or CSRF protection. Fix: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/commit/169eed84f558108d1f223e3de04d2eb7d1895879

### Review

After removing the csrf.disable() line in SecurityConfig, and replacing @GetMapping with @PostMapping in NoteController.deleteNote, the csrf link from MA 2: 
http://localhost:8080/note/delete/01922d68-0c26-702b-8c6f-f3a55c9f737a
is no longer able to delete the note from Alice’s user. Deleting notes still works as intended in the dashboard.

Link to merge request with review.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/3

## Authentication Improvement (3 pts)

The authentication in InShare relies on Spring Security and InShareUserDetailsService to load user details from the SQLite database.

Passwords are currently being stored and retrieved without hashing ("{noop}" + password in User.getPassword). Passwords are accessible in plain text in the database, which is a significant security risk.

In addition to insecure storage of passwords, there are no requirements for the complexity of user’s chosen passwords. User’s may choose weak passwords that pose a security threat. 

### Planning

Implementing requirements for password complexity during registration. This will be similar to the username validation in the SQL mitigation.

Password hashing: I will attempt to implement hashing using BCrypt which is supported in the Spring Security framework. Compared to other hashing algorithms/tools, it seems to have a few advantages. For instance, there is a built-in salting mechanism to automatically generate a unique salt for each password, which is included in the final hash. This salt protects against rainbow table attacks by ensuring that even identical passwords result in different hashes. 

Link to issue(s) created.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/issues/6

### Implementation
There was only one commit before merging: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/4/diffs?commit_id=176477b9aa30e9ac13a41895ac3cd371f9b4d326

### Review

After implementing password requirements for registration, I tried to register a new user with password “Password123”. This caused the expected alert 'Invalid password', informing about the password requirements. 

After implementing password hashing with BCrypt, I registered a two new users ‘Andy’ and ‘Wilma’, both with password ‘Password123!’. Checking the database table verified that both Andy’s and Wilma’s passwords are successfully hashed before being saved to the database. In addition, the salting mechanism in BCrypt ensures that the two passwords are stored as different hashes, even though the passwords are identical.

However, passwords containing words like 'password' are not very secure and should also be invalid. This is something I would improve if I had more time.

Link to merge request with review.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/4


## Access Control Improvement (4 pts)
InShare uses a Discretionary Access Control (DAC) model and primarily UI-based restrictions. With DAC, the permission checks are loosely defined, lacking clear, role-specific permissions. This results in ambiguity over who can perform actions like editing or deleting notes, leading to potential unauthorized access. Many permissions are enforced only at the UI level, meaning users can bypass access controls by making direct requests to endpoints. This allows unauthorized users to potentially edit, delete, or share notes if they know the API paths. The DAC model does not enforce a single-owner policy for notes, allowing unauthorized users to modify ownership or promote themselves to the OWNER role. This creates confusion and security risks over note control. Since permissions are not centrally managed by roles, tracking or auditing user permissions is challenging. This lack of transparency makes it difficult to identify and mitigate potential security risks in user access.

### Planning
Plan for the creation of a Role Based Access Control (RBAC) for InShare:
New database tables:
Roles: Stores role names ("owner," "administrator," "editor," "reader").
UserRoles: Establishes a relationship between users, notes, and roles, allowing multiple roles per user on each note.

Roles:
- "owner": Each note has a unique owner. Has read/write/delete permissions. Cannot be revoked, only transferred by the owner themselves.
- "administrator": Has read/write/delete permissions. Can set roles (except owner).
- "editor": Has read/write permissions.
- "reader": Can only read the note.

Backend permission checks: 
Implement in NoteController methods to enforce permission checks to ensure that only authorized users can perform certain actions on notes. 

UI coordination:
The UI complements the backend checks by conditionally displaying or hiding options like "Edit," "Delete," and "Share" based on the user's permissions, in dashboard.html.

Link to Issue 4 Access Control: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/issues/5

### Implementation
At first, the aim was just to implement an RBAC model and maintaining the application’s functionality. The implemented model seemed to work quite well, except for some issues with note sharing. This was improved by implementing restrictions for which roles could see the “share” button in the UI, and also improving permission checks in the backend.
Link to fix commits: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/5/diffs?commit_id=fa23e1475c6cd576e515c22f1fef2d1dd446ca97
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/5/diffs?commit_id=62a46f04fdca45cb190c639d9e0bafd1642ce47e

After peer review, it was pointed out that some illegal actions were still possible through fetch requests. This was solved through improving the permission checks.
Link to fix commit: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/5/diffs?commit_id=36b6e4b46417b0df960752dce6657854acebaa23

Finally, I improved the functionality of ownership transfers, so that there could only be one owner of a note.
Fix commit: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/5/diffs?commit_id=4adfa8e4e5f63ed00c47b4c1c72713b859e75a8a


### Review
The new RBAC model was tested by using the application and all of it's functionality related to roles. Permission checks were tested using fetch requests targeting actions from users without the correct role/permissions. I also verified that the UI does not show options for performing actions without the correct role/permissions.

Link to merge request with review: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/5?commit_id=4adfa8e4e5f63ed00c47b4c1c72713b859e75a8a

## Logging System Improvement (1 pts)

Security logging provides a traceable record of significant actions in an application, essential for detecting, investigating, and responding to incidents. By logging key events with integrity and consistency, we can audit changes, trace potential threats, and identify vulnerabilities. Effective logging supports accountability, simplifies debugging, and strengthens overall security.

### Planning

There is currently very little logging going on in InShare. The only current logging is in:
- SQLiteConfig.java: Logs when foreign key support is enabled in SQLite.
- Note.java: Logs when roles and notes are loaded from the database.

Plan for further logging in InShare
Authentication events:
Track login attempts and detect suspicious login activities.
- Log successful logins and failed login attempts.
- Log successful logouts.
- Log level: INFO for success, WARN for failure.

Do not log passwords, tokens, or sensitive session data. Only include general user identifiers like username or user ID.

Note Actions:
Logging note actions provides a transparent audit trail of user activities involving notes, including creation, editing, deletion, and sharing. This helps in both monitoring user behavior and investigating issues if unauthorized or suspicious activities arise.

- Log each action that modifies a note, such as creating, editing, deleting, sharing or transferring ownership.
- Log level: INFO for standard actions (create, edit) and WARN for sensitive actions (delete, share, transfer ownership).

Avoid logging the note’s content, any confidential information within the note, or any personal data associated with the note or user. Only use identifiers. Limit logs to essential information. Avoid logging user roles and permissions unless they are critical for security investigation.

Security Threat Detection:
Monitor and record potential security threats or attempts to compromise the application. This includes logging for unauthorized access attempts, and can be exapanded for e.g. sql injection and xss attempts.

Unauthorized Access Attempts: Log unauthorized access attempts, especially if a user tries to perform actions outside their permission scope.

Avoid logging the exact input data or payloads (especially if they might contain harmful scripts or sensitive information). Instead, log the type of detection and which user (if authenticated) attempted the action. Limit logs to essential information; avoid logging benign details that don’t aid in understanding potential threats.

Recommendations for log monitoring and response for InShare:
The implemented logging setup would benefit from enhancements to support comprehensive security monitoring and response. Logs should ideally be aggregated and analyzed by an external logging service (maybe cloud-based) rather than stored in the database, which lacks the analytic capabilities required for robust monitoring.

Key security events—such could be configured in the log monitoring system to notify administrators of potential threats. Incident response routines should also be developed for each alert type, outlining clear protocols to follow when a threat is detected. These responses might range from notifying relevant staff to suspending suspicious accounts or IP addresses until a review is conducted.

Log security is critical, so logs should be stored securely, with access restricted to authorized personnel, and retained in compliance with regulatory standards. A monitoring dashboard could be set up to visualize key metrics, enabling administrators to spot unusual activity quickly. Regular audits and threat simulations would further strengthen the logging and response framework, ensuring that InShare can handle real-world security demands effectively.

Link to Issue 6 Logging: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/issues/7

### Implementation

I had some trouble with the logging for unauthorized access attempts on note actions. When the illegal action was "blocked" by the implemented security measures, it was not logged. This was solved implementing the new CustomAccessDeniedHandler class. 

Commit implementing logging for authentication: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/6/diffs?commit_id=3985d1a7fd4515732e9a52f8331dbe5f376d4290
Commit implementing logging for note actions: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/6/diffs?commit_id=1d7aad5f1c4c58a6804bb3acc33e2988aa9da03c
Commit implementing logging for unauthorized access attempts: https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/6/diffs?commit_id=f62aef806e8d743075956e33ae0b88714d503023

### Review
All logging instances were tested by performing the actions involved. I would like to implement a distinction between SHARE note attempts and TRANSFER ownership in CustomAccessDeniedHandler.java, but did not have time.

Did not have time for peer review.
https://git.app.uib.no/kaja.kiberg-tveit/inshare/-/merge_requests/6