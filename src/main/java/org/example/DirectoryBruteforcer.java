package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

public class DirectoryBruteforcer {

    private static List<String> commonDirectories = new ArrayList<>();

    // Метод для загрузки списка директорий из файла
    public static void loadCommonDirectories(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                commonDirectories.add(line.trim());
            }
        }
    }

    // Предустановленный список директорий
    public static List<String> getPredefinedList() {
        return Arrays.asList(
                "/admin",
                "/login",
                "/dashboard",
                "/user",
                "/test",
                "/api",
                "/public",
                "/private",
                "/config",
                "/configurations",
                "/settings",
                "/account",
                "/accounts",
                "/profile",
                "/profiles",
                "/secure",
                "/auth",
                "/authentication",
                "/authorize",
                "/authorization",
                "/adminpanel",
                "/admincp",
                "/adminconsole",
                "/adminarea",
                "/controlpanel",
                "/cp",
                "/management",
                "/manager",
                "/system",
                "/sys",
                "/data",
                "/database",
                "/db",
                "/backup",
                "/backups",
                "/files",
                "/uploads",
                "/download",
                "/downloads",
                "/static",
                "/assets",
                "/scripts",
                "/js",
                "/css",
                "/images",
                "/img",
                "/photos",
                "/media",
                "/log",
                "/logs",
                "/debug",
                "/debugging",
                "/monitor",
                "/monitoring",
                "/error",
                "/errors",
                "/issues",
                "/status",
                "/statuspage",
                "/health",
                "/healthcheck",
                "/maintenance",
                "/maint",
                "/update",
                "/updates",
                "/patch",
                "/patches",
                "/version",
                "/versions",
                "/v1",
                "/v2",
                "/v3",
                "/old",
                "/new",
                "/beta",
                "/alpha",
                "/staging",
                "/test",
                "/testing",
                "/qa",
                "/qualityassurance",
                "/development",
                "/dev",
                "/developer",
                "/developers",
                "/docs",
                "/documentation",
                "/support",
                "/help",
                "/faq",
                "/contact",
                "/contacts",
                "/feedback",
                "/report",
                "/reports",
                "/reporting",
                "/analytics",
                "/stats",
                "/statistics",
                "/graph",
                "/graphs",
                "/chart",
                "/charts",
                "/dashboard",
                "/home",
                "/index",
                "/main",
                "/root",
                "/welcome"
        );
    }

    // Загруженный список директорий
    public static List<String> getCustomList() {
        return new ArrayList<>(commonDirectories);
    }

    // Метод для проверки директории
    public static String checkDirectory(String url, String directory) throws IOException {
        String fullUrl = url + directory;
        String statusCode = Fuzzer.sendRequest(fullUrl);
        if (statusCode.equals("200")) {
            return fullUrl;
        }
        return "";
    }

    // Метод для многопоточной проверки директорий
    public static List<Future<String>> bruteforceDirectories(String url, List<String> directories, ExecutorService executorService) {
        List<Future<String>> futures = new ArrayList<>();
        for (String dir : directories) {
            Callable<String> task = () -> checkDirectory(url, dir);
            futures.add(executorService.submit(task));
        }
        return futures;
    }
}
