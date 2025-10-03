# My PhP PACS
Overview
This Picture Archiving and Communication System (PACS) is a web-based application for managing and viewing DICOM medical imaging files. It supports uploading, searching, viewing, and deleting DICOM files, with a user-friendly interface powered by Bootstrap and the DWV (DICOM Web Viewer). The application is designed to run on shared hosting environments with PHP and MySQL support, such as those provided by Bluehost, SiteGround, DreamHost, or similar servers, with a user-choosable installation directory.
Features

Upload: Admins can upload DICOM (.dcm) files with metadata parsing using the Nanodicom library.
Search: Users can search DICOM files by patient name, ID, modality, and other metadata fields.
View: View DICOM files using the DWV viewer.
Delete: Admins can delete DICOM files from the server and database.
Role-Based Access: Admin (full access) and public user (search/view only) roles.
Responsive Design: Mobile-friendly interface with Bootstrap 5.3.3.
Flexible Installation: Choose any directory for installation (e.g., public_html/pacs).

Prerequisites
To deploy this PACS application, ensure your hosting environment meets the following requirements:

Web Server: Apache or similar with PHP support (e.g., Bluehost, SiteGround, DreamHost).
PHP: Version 7.4 or higher with the following extensions enabled:
mysqli (for database connectivity)
zip (for extracting DWV)
fileinfo (for file type validation)
gd (for image processing)


PHP Settings (configurable in your hosting control panel):
upload_max_filesize: 32M
post_max_size: 32M
max_execution_time: 300


MySQL Database: A MySQL database with a user having full privileges, created via your hosting control panel.
Domain/Subdomain: A domain or subdomain (e.g., pacs.example.com) pointing to the chosen installation directory.
Nanodicom Library: Required for DICOM metadata parsing (manually uploaded).
DWV Viewer: Version 0.11.0, either downloaded automatically or manually uploaded.
SSL/TLS: HTTPS enabled for secure access (most hosting providers offer free SSL via AutoSSL or Let’s Encrypt).

Installation
Follow these steps to install the PACS application on your web server:

Prepare the Directory:

Decide on an installation directory (e.g., /home/username/public_html/pacs/ or /home/username/myapp/).
Upload the install_pacs.php script to this directory using your hosting control panel’s File Manager or FTP.
Set permissions: chmod 755 for the directory and chmod 644 for install_pacs.php.


Run the Installation Script:

Access the script via your browser: https://yourdomain.com/<install_dir>/install_pacs.php (replace <install_dir> with your chosen directory, e.g., pacs).
Complete the installation form:
Hospital Name: Name for the app (max 100 characters, displayed in titles).
Domain: Your domain or subdomain (e.g., pacs.example.com).
Installation Directory: Path relative to your home directory (e.g., public_html/pacs).
Database Host: Usually localhost for shared hosting.
Database Name: MySQL database name (e.g., user_pacs).
Database Username: MySQL user with full privileges.
Database Password: Password for the MySQL user.
Favicon: PNG or JPG (32x32 or 64x64 pixels).
Site Logo: PNG or JPG (100x30 to 300x100 pixels).


Submit the form to start the installation.


Installation Process:

The script validates inputs, checks the database connection, and ensures the installation directory is writable.
If errors occur (e.g., invalid favicon, database issues, unwritable directory), they’ll be displayed for correction.
Upon success, the script:
Creates directories: /<install_dir>/, /<install_dir>/dwv/, /<install_dir>/dicom-storage/, /<install_dir>/css/, /<install_dir>/sessions/, /<install_dir>/nanodicom/.
Downloads and extracts DWV v0.11.0 to /<install_dir>/dwv/ (if allow_url_fopen and zip are enabled; otherwise, manual upload required).
Generates files: config.php, session.php, login.php, index.php, search.php, delete.php, upload.php, css/style.css.
Creates the MySQL dicom_files table for storing DICOM metadata.
Logs actions to /home/username/install_log.txt.




Post-Installation Steps:

Enable HTTPS: Use your hosting control panel to enable SSL/TLS (e.g., AutoSSL or Let’s Encrypt).
Verify Files:
Check /<install_dir>/config.php for correct database credentials, domain, and hospital name.
Ensure /<install_dir>/sessions/ exists and is chmod 700.
Confirm favicon (/<install_dir>/favicon.png or .jpg) and logo (/<install_dir>/logo.png or .jpg).


Nanodicom Library:
Download the Nanodicom library from its official source or a trusted repository.
Upload nanodicom.php and the dicom/ folder to /<install_dir>/nanodicom/.
Set permissions: chmod 755 /<install_dir>/nanodicom/, chmod 644 /<install_dir>/nanodicom/*.php, chmod 644 /<install_dir>/nanodicom/dicom/*.


DWV Viewer (if auto-download failed):
Download DWV v0.11.0 from https://github.com/ivmartel/dwv/releases/tag/v0.11.0.
Extract and upload the viewers/ contents to /<install_dir>/dwv/.


Set Permissions:
Directories (/<install_dir>/, /<install_dir>/dicom-storage/, /<install_dir>/dwv/, /<install_dir>/css/, /<install_dir>/nanodicom/): chmod 755.
Files (/<install_dir>/*.php, /<install_dir>/css/style.css, favicon, logo, Nanodicom files): chmod 644.
Sessions directory (/<install_dir>/sessions/): chmod 700.


Verify PHP Settings: Confirm upload_max_filesize, post_max_size, and max_execution_time in your control panel.
Domain Setup: Ensure your domain/subdomain points to /home/username/<install_dir>/.
Delete Installation Script: Remove /<install_dir>/install_pacs.php for security.
Test the Application:
Login: https://yourdomain.com/login.php (use admin/docentelasmercedes or user/1234).
Upload (admin): https://yourdomain.com/index.php.
Search: https://yourdomain.com/search.php.
View (DWV): https://yourdomain.com/dwv/viewers/mobile/.
Delete (admin): https://yourdomain.com/delete.php.
Test with a sample DICOM file from https://www.dicomlibrary.com.





Usage

Login:
Admin: Username: admin, Password: docentelasmercedes (full access to upload/delete).
User: Username: user, Password: 1234 (search/view only).


Upload DICOM Files (admin only):
Go to index.php, select a .dcm file, and upload.
Metadata is parsed and stored in the database.


Search DICOM Files:
Use search.php to search by patient name, ID, modality, etc.
Results include links to view files in DWV.


View DICOM Files:
Access the DWV viewer via dwv/viewers/mobile/ or search result links.


Delete DICOM Files (admin only):
Use delete.php to select and delete files from the server and database.


Debugging:
Check /home/username/install_log.txt, /<install_dir>/login_debug.txt, and /<install_dir>/login_error.log for issues.



Troubleshooting

Database Errors: Verify credentials in config.php and ensure the MySQL user has full privileges.
Upload Issues: Check PHP settings (upload_max_filesize, post_max_size) and directory permissions.
DWV Viewer Not Loading: Confirm /<install_dir>/dwv/ contains the viewer files.
Nanodicom Errors: Ensure /<install_dir>/nanodicom/nanodicom.php and /<install_dir>/nanodicom/dicom/ exist.
Permission Issues: Recheck directory (755) and file (644) permissions.

Security Notes

Delete install_pacs.php after installation.
Use HTTPS to secure data transmission.
Change default admin/user passwords in config.php for production use.
Regularly back up the database and /<install_dir>/dicom-storage/ directory.

License
This project is provided as-is for educational and non-commercial use. Ensure compliance with the Nanodicom and DWV licenses when using their libraries.
