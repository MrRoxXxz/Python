import os
import platform

def install_db():
    # check the distribution type
    system = platform.system()
    if system == "Windows":
        # check if the system has a database software installed
        if os.system("sc query state= all | findstr /C:\"SQL Server\"") == 0:
            print("A database software is already installed.")
        else:
            # install an open-source database solution for Windows
            os.system("choco install sql-server-express")
    elif system == "Linux":
        distro = platform.linux_distribution()[0].lower()
        # check if the system has a database software installed
        if os.system("dpkg -s mysql-server") == 0 or os.system("rpm -q mariadb-server") == 0:
            print("A database software is already installed.")
        else:
            # install an open-source database solution based on the Linux distribution
            if distro in ["centos", "red hat"]:
                os.system("sudo yum install mariadb-server")
            elif distro in ["ubuntu", "debian"]:
                os.system("sudo apt-get install mysql-server")
            else:
                print("The script does not support this distribution.")
    else:
        print("The script does not support this operating system.")

install_db()
