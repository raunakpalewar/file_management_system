# file_management_system
File_management sytem based on django drf topic


Problem Statement : 

Create a django file management app using the rest framework. It needs to have the following features
- There will be two user groups as Owner and Staff. Owner can add staff members under him
- All users can upload, view and manage their respective files and folders in the dashboard.
- Under the same company, users can share files/ documents and assign document tasks to each other.

Project Description:

File Management System using Django REST Framework

This Django-based File Management System is designed to streamline file handling for businesses with distinct user roles - Owners and Staff. The application provides an intuitive interface for file uploads, organization, and sharing, ensuring efficient collaboration within a company. Users are categorized into Owners and Staff members, with Owners having the authority to manage staff, while both user groups can upload, view, and manage their files and folders. Additionally, within the same company, users can share files and assign document-related tasks, enhancing teamwork and productivity.

API Summary:

Owner Registration:

Endpoint: /owner/registration/
Description: Allows Owners to register and create their accounts.
Staff Registration:

Endpoint: /staff/registration/
Description: Enables Staff members to register under an Owner's account.
Email Verification:

Endpoint: /verify/email/
Description: Verifies the user's email address.
User Login:

Endpoint: /login/
Description: Allows users to log in to their accounts.
User Logout:

Endpoint: /logout/
Description: Logs the user out, terminating the session.
Forgot Password:

Endpoint: /forgot/password/
Description: Handles password recovery requests.
Set New Password:

Endpoint: /set/new/password/
Description: Allows users to set a new password after recovery.
Company Registration:

Endpoint: /CompanyRegistration/
Description: Permits Owners to register their companies.
Add Staff to Company:

Endpoint: /AddStaffToCompany/
Description: Allows Owners to add staff members to their companies.
File Upload:

Endpoint: /FileUploadAPI/
Description: Enables all users to upload files to their respective accounts.
File Transfer:

Endpoint: /fileTransfer/
Description: Allows users to transfer files to other staff members within the same company.
File List View:

Endpoint: /FileListView/
Description: Displays a list of files belonging to the authenticated user.
Total APIs: 12

This File Management System provides a robust and secure platform for businesses to handle their documents efficiently, fostering collaboration and enhancing productivity among team members.




 
