package org.example;

import javafx.application.Application;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class FuzzerJava extends Application {

    @Override
    public void start(Stage primaryStage) {
        VBox root = new VBox();
        root.setSpacing(10);
        root.setAlignment(Pos.TOP_CENTER);
        root.getStyleClass().add("root");

        // Информация
        Label appInfoLabel = new Label("Fuzzer - это инструмент для тестирования, позволяющий найти уязвимости в веб-приложениях");
        appInfoLabel.setWrapText(true);
        appInfoLabel.getStyleClass().add("label-background");

        // Контейнер для поля ввода и кнопки проверки доступности
        HBox inputBox = new HBox();
        inputBox.setSpacing(10);
        inputBox.setAlignment(Pos.CENTER);
        inputBox.getStyleClass().add("input-box");

        // URL
        TextField urlTextField = new TextField();
        urlTextField.setPromptText("Введите URL адрес");
        urlTextField.getStyleClass().add("text-field");

        Button checkAvailabilityButton = new Button("Проверить доступность");
        checkAvailabilityButton.setMinWidth(180);
        checkAvailabilityButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки проверки доступности
        checkAvailabilityButton.setOnAction(event -> {
            String url = urlTextField.getText();
            String statusCode = Fuzzer.sendRequest(url);
            if (statusCode.equals("Неверно введен URL")) {
                displayError(statusCode);
            } else {
                displayResponse(statusCode);
            }
        });

        // Полоса с надписью "Методы фаззинга"
        HBox separatorBox1 = new HBox();
        separatorBox1.setAlignment(Pos.CENTER);
        separatorBox1.setSpacing(10);
        separatorBox1.setPrefWidth(638);

        Separator leftSeparator1 = new Separator();
        Label fuzzingMethodsLabel = new Label("Методы фаззинга");
        fuzzingMethodsLabel.setStyle("-fx-font-size: 16px; -fx-text-fill: white;");
        Separator rightSeparator1 = new Separator();

        separatorBox1.getChildren().addAll(leftSeparator1, fuzzingMethodsLabel, rightSeparator1);
        HBox.setHgrow(leftSeparator1, Priority.ALWAYS);
        HBox.setHgrow(rightSeparator1, Priority.ALWAYS);

        // Контейнер для поля ввода и кнопки фаззинга
        VBox fuzzingBox = new VBox();
        fuzzingBox.setSpacing(10);
        fuzzingBox.setAlignment(Pos.CENTER);
        fuzzingBox.getStyleClass().add("fuzzing-box");

        Button startFuzzingButton = new Button("Начать Http фаззинг");
        startFuzzingButton.setMinWidth(220);
        startFuzzingButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки фаззинга
        startFuzzingButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                StringBuilder responses = new StringBuilder();
                responses.append("GET: ").append(HttpFuzzer.sendGet(url)).append("\n");
                responses.append("POST: ").append(HttpFuzzer.sendPost(url, "{\"name\":\"test\"}")).append("\n");
                responses.append("PUT: ").append(HttpFuzzer.sendPut(url, "{\"name\":\"test\"}")).append("\n");
                responses.append("DELETE: ").append(HttpFuzzer.sendDelete(url)).append("\n");
                displayAllResponses(responses.toString());
            } catch (IOException e) {
                displayError("Ошибка при выполнении запросов: " + e.getMessage());
            }
        });

        // Контейнер для кнопки фаззинга заголовков
        Button startHeaderFuzzingButton = new Button("Начать фаззинг заголовков");
        startHeaderFuzzingButton.setMinWidth(220);
        startHeaderFuzzingButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки фаззинга заголовков
        startHeaderFuzzingButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                Map<String, String> headers = HeaderFuzzer.generateHeaders();
                String response = HeaderFuzzer.sendGetWithHeaders(url, headers);
                displayAllResponses("GET с заголовками: " + response);
            } catch (IOException e) {
                displayError("Ошибка при выполнении запросов: " + e.getMessage());
            }
        });

        // "Обнаружение директорий"
        HBox separatorBox2 = new HBox();
        separatorBox2.setAlignment(Pos.CENTER);
        separatorBox2.setSpacing(10);
        separatorBox2.setPrefWidth(638);

        Separator leftSeparator2 = new Separator();
        Label directoryDiscoveryLabel = new Label("Обнаружение директорий");
        directoryDiscoveryLabel.setStyle("-fx-font-size: 16px; -fx-text-fill: white;");
        Separator rightSeparator2 = new Separator();

        separatorBox2.getChildren().addAll(leftSeparator2, directoryDiscoveryLabel, rightSeparator2);
        HBox.setHgrow(leftSeparator2, Priority.ALWAYS);
        HBox.setHgrow(rightSeparator2, Priority.ALWAYS);

        // Контейнер для кнопок брутфорса директорий
        VBox directoryBruteforceBox = new VBox();
        directoryBruteforceBox.setSpacing(10);
        directoryBruteforceBox.setAlignment(Pos.CENTER);
        directoryBruteforceBox.getStyleClass().add("fuzzing-box");

        // Кнопка для брутфорса директорий с использованием заранее заданного списка
        Button startPredefinedDirectoryBruteforceButton = new Button("Начать брутфорс директорий (предустановленные)");
        startPredefinedDirectoryBruteforceButton.setMinWidth(300);
        startPredefinedDirectoryBruteforceButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки брутфорса с предустановленным списком
        startPredefinedDirectoryBruteforceButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                StringBuilder directoryListing = new StringBuilder();
                directoryListing.append("Найденные директории:\n");
                String[] directories = DirectoryBruteforcer.bruteforceDirectoriesWithPredefinedList(url);
                for (String dir : directories) {
                    directoryListing.append(dir).append("\n");
                }
                displayAllResponses(directoryListing.toString());
            } catch (IOException e) {
                displayError("Ошибка при выполнении брутфорса директорий: " + e.getMessage());
            }
        });

        // Кнопка для брутфорса директорий с использованием загруженного списка
        Button startCustomDirectoryBruteforceButton = new Button("Начать брутфорс директорий (загруженные)");
        startCustomDirectoryBruteforceButton.setMinWidth(300);
        startCustomDirectoryBruteforceButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки брутфорса с загруженным списком
        startCustomDirectoryBruteforceButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                StringBuilder directoryListing = new StringBuilder();
                directoryListing.append("Найденные директории:\n");
                String[] directories = DirectoryBruteforcer.bruteforceDirectories(url);
                for (String dir : directories) {
                    directoryListing.append(dir).append("\n");
                }
                displayAllResponses(directoryListing.toString());
            } catch (IOException e) {
                displayError("Ошибка при выполнении брутфорса директорий: " + e.getMessage());
            }
        });

        // Кнопка для загрузки файла с директориями
        Button loadDirectoriesButton = new Button("Загрузить список директорий");
        loadDirectoriesButton.setMinWidth(300);
        loadDirectoriesButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки загрузки списка директорий
        loadDirectoriesButton.setOnAction(event -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Выберите файл со списком директорий");
            File file = fileChooser.showOpenDialog(primaryStage);
            if (file != null) {
                try {
                    DirectoryBruteforcer.loadCommonDirectories(file.getAbsolutePath());
                    displayResponse("Список директорий успешно загружен");
                } catch (IOException e) {
                    displayError("Ошибка при загрузке файла: " + e.getMessage());
                }
            }
        });

        // Разделитель "Поиск уязвимостей"
        HBox separatorBox3 = new HBox();
        separatorBox3.setAlignment(Pos.CENTER);
        separatorBox3.setSpacing(10);
        separatorBox3.setPrefWidth(638);
        Separator leftSeparator3 = new Separator();
        Separator rightSeparator3 = new Separator();
        Label vulnerabilitiesLabel = new Label("Поиск уязвимостей");
        vulnerabilitiesLabel.setStyle("-fx-font-size: 16px; -fx-text-fill: red;");

        separatorBox3.getChildren().addAll(leftSeparator3, vulnerabilitiesLabel, rightSeparator3);
        HBox.setHgrow(leftSeparator3, Priority.ALWAYS);
        HBox.setHgrow(rightSeparator3, Priority.ALWAYS);

        // Кнопка для фаззинга SQL инъекций
        Button startSQLInjectionFuzzingButton = new Button("Начать SQL Injection фаззинг");
        startSQLInjectionFuzzingButton.setMinWidth(220);
        startSQLInjectionFuzzingButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки фаззинга SQL инъекций
        startSQLInjectionFuzzingButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                String response = SQLInjectionFuzzer.fuzzSQLInjection(url);
                displayAllResponses("SQL Injection фаззинг: " + response);
            } catch (IOException e) {
                displayError("Ошибка при выполнении SQL Injection фаззинга: " + e.getMessage());
            }
        });
        // Кнопка для Directory Traversal фаззинга
        Button startDirectoryTraversalFuzzingButton = new Button("Начать Directory Traversal фаззинг");
        startDirectoryTraversalFuzzingButton.setMinWidth(220);
        startDirectoryTraversalFuzzingButton.getStyleClass().add("button");

// Устанавливаем обработчик событий для кнопки фаззинга Directory Traversal
        startDirectoryTraversalFuzzingButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                String response = DirectoryTraversalFuzzer.fuzzDirectoryTraversal(url).toString();
                displayAllResponses("Directory Traversal фаззинг: " + response);
            } catch (IOException e) {
                displayError("Ошибка при выполнении Directory Traversal фаззинга: " + e.getMessage());
            }
        });

        inputBox.getChildren().addAll(urlTextField, checkAvailabilityButton);
        fuzzingBox.getChildren().addAll(separatorBox1, startFuzzingButton, startHeaderFuzzingButton);
        directoryBruteforceBox.getChildren().addAll(separatorBox2, startPredefinedDirectoryBruteforceButton, startCustomDirectoryBruteforceButton);

        root.getChildren().addAll(appInfoLabel, inputBox, fuzzingBox, directoryBruteforceBox, loadDirectoriesButton, separatorBox3, startDirectoryTraversalFuzzingButton,  startSQLInjectionFuzzingButton);

        Scene scene = new Scene(root, 700, 600);
        scene.getStylesheets().add("styles.css");

        primaryStage.setTitle("Fuzzer");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void displayResponse(String response) {
        Stage responseStage = new Stage();
        responseStage.setTitle("Ответ");

        VBox responseBox = new VBox();
        responseBox.setSpacing(10);
        responseBox.setAlignment(Pos.CENTER);
        responseBox.getStyleClass().add("response-box");

        TextArea responseTextArea = new TextArea(response);
        responseTextArea.setWrapText(true);
        responseTextArea.setEditable(false);
        responseTextArea.getStyleClass().add("response-text-area");

        Button closeButton = new Button("Закрыть");
        closeButton.setMinWidth(100);
        closeButton.getStyleClass().add("button");

        closeButton.setOnAction(event -> responseStage.close());

        responseBox.getChildren().addAll(responseTextArea, closeButton);

        Scene responseScene = new Scene(responseBox, 400, 300);
        responseScene.getStylesheets().add("org/example/style.css");

        responseStage.setScene(responseScene);
        responseStage.show();
    }

    private void displayError(String error) {
        displayResponse("Ошибка: " + error);
    }

    private void displayAllResponses(String responses) {
        displayResponse(responses);
    }

    public static void main(String[] args) {
        launch(args);
    }
}
