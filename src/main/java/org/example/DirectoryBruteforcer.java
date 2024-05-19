package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class DirectoryBruteforcer {

    private static List<String> COMMON_DIRECTORIES = new ArrayList<>();

    // Заранее заданный список директорий
    private static final String[] PREDEFINED_DIRECTORIES = {
            "admin", "administrator", "login", "wp-admin", "wp-login", "user", "users",
            "adminpanel", "loginpanel", "admin/login", "admin/admin", "admin_area", "panel-administracion",
            "panel-admin", "admincontrol", "admincp", "admin/index", "administrator/index",
            "cpanel", "admin.php", "admin.html", "admin/login.php", "admin/login.html",
            "admin/admin.php", "admin/admin.html", "login.php", "login.html", "home", "main",
            "test", "tmp", "dev", "admin/", "administrator/", "webadmin/", "webadmin.php",
            "adminlogin/", "adminlogin.php", "admin_area/admin", "admin_area/login", "admin_area/index",
            "bb-admin", "bb-admin/login", "bb-admin/admin", "admin/home", "admin/controlpanel", "admin/adminLogin",
            "admin/admin-login", "admin-login", "admin-cp", "adminpanel", "webadmin", "webadmin/login",
            "admin/admin_login", "admin/adminlogin", "admin-login.php", "admin-login.html", "admin/adminLogin.php",
            "admin/adminLogin.html", "admin/admin-login.php", "admin/admin-login.html", "admin/cp.php", "admin/cp.html",
            "cp.php", "cp.html", "adminpanel.php", "adminpanel.html", "admincp/index.asp", "admincp/index.html",
            "admincp/login.asp", "admincp/login.html", "admincp/login.aspx", "admincp/login.php", "admincp/login.jsp",
            "admin/index.html", "admin/index.php", "admin/login.html", "admin/login.php", "admin/admin_login.php",
            "admin/admin_login.html", "admin/admin-login.html", "admin/admin-login.php", "admin/adminLogin.html",
            "admin/controlpanel.html", "admin/controlpanel.php", "admin/adminLogin.php", "admin/admin-login.jsp",
            "admin/adminLogin.jsp", "admin/adminLogin.aspx", "admin/admin-login.aspx", "admin/adminLogin.jsf",
            "admin/admin-login.jsf", "admin/controlpanel.jsf", "admin/control-panel.php", "admin/cp.php",
            "cp.html", "cp.php", "admincp/index.asp", "admincp/index.html", "admincp/login.asp", "admincp/login.html",
            "admincp/login.aspx", "admincp/login.php", "admincp/login.jsp", "admincp/index.html", "admincp/index.php",
            "admin/login.html", "admin/login.php", "admin/admin_login.php", "admin/admin_login.html",
            "admin/admin-login.html", "admin/admin-login.php", "admin/adminLogin.html", "admin/controlpanel.html",
            "admin/controlpanel.php", "admin/adminLogin.php", "admin/admin-login.jsp", "admin/adminLogin.jsp",
            "admin/adminLogin.aspx", "admin/admin-login.aspx", "admin/adminLogin.jsf", "admin/admin-login.jsf",
            "admin/controlpanel.jsf", "admin/control-panel.php", "admin/cp.php", "cp.html", "cp.php",
            "admincp/index.asp", "admincp/index.html", "admincp/login.asp", "admincp/login.html",
            "admincp/login.aspx", "admincp/login.php", "admincp/login.jsp", "admincp/index.html",
            "admincp/index.php", "admin/login.html", "admin/login.php", "admin/admin_login.php",
            "admin/admin_login.html", "admin/admin-login.html", "admin/admin-login.php", "admin/adminLogin.html",
            "admin/controlpanel.html", "admin/controlpanel.php", "admin/adminLogin.php", "admin/admin-login.jsp",
            "admin/adminLogin.jsp", "admin/adminLogin.aspx", "admin/admin-login.aspx", "admin/adminLogin.jsf",
            "admin/admin-login.jsf", "admin/controlpanel.jsf", "admin/control-panel.php", "admin/cp.php",
            "cp.html", "cp.php", "admincp/index.asp", "admincp/index.html", "admincp/login.asp",
            "admincp/login.html", "admincp/login.aspx", "admincp/login.php", "admincp/login.jsp",
            "admincp/index.html", "admincp/index.php", "admin/login.html", "admin/login.php",
            "admin/admin_login.php"
    };

    // Метод для загрузки списка директорий из файла
    public static void loadCommonDirectories(String filePath) throws IOException {
        COMMON_DIRECTORIES.clear();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                COMMON_DIRECTORIES.add(line.trim());
            }
        }
    }

    // Метод для брутфорса директорий с использованием загруженного списка
    public static String[] bruteforceDirectories(String baseUrl) throws IOException {
        List<String> foundDirectories = new ArrayList<>();
        for (String dir : COMMON_DIRECTORIES) {
            String url = baseUrl + (baseUrl.endsWith("/") ? "" : "/") + dir;
            if (Fuzzer.sendRequest(url).equals("200 OK")) {
                foundDirectories.add(dir);
            }
        }
        return foundDirectories.toArray(new String[0]);
    }

    // Метод для брутфорса директорий с использованием заранее заданного списка
    public static String[] bruteforceDirectoriesWithPredefinedList(String baseUrl) throws IOException {
        List<String> foundDirectories = new ArrayList<>();
        for (String dir : PREDEFINED_DIRECTORIES) {
            String url = baseUrl + (baseUrl.endsWith("/") ? "" : "/") + dir;
            if (Fuzzer.sendRequest(url).equals("200 OK")) {
                foundDirectories.add(dir);
            }
        }
        return foundDirectories.toArray(new String[0]);
    }
}
