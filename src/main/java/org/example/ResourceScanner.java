package org.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class ResourceScanner {

    public static String scanResource(String urlString) throws IOException {
        StringBuilder result = new StringBuilder();
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int status = connection.getResponseCode();
        result.append("HTTP Status: ").append(status).append("\n");

        // Заголовки
        Map<String, List<String>> headers = connection.getHeaderFields();
        result.append("\nHeaders:\n");
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            result.append(header.getKey()).append(": ").append(header.getValue()).append("\n");
        }

        // Содержимое HTML
        result.append("\nContent:\n");
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            result.append(inputLine).append("\n");
        }
        in.close();

        // Запись в файл
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("output.txt"))) {
            writer.write(result.toString());
        }

        // Возвращаем сообщение о сохранении в файл
        return "Отчет сохранен в файл output.txt\n\n" + result.toString();
    }
}
