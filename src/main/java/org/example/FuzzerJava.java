package org.example;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.scene.image.Image;

public class FuzzerJava extends Application {

    @Override
    public void start(Stage primaryStage) {
        VBox root = new VBox();
        root.setSpacing(10);

        // Информация
        Label appInfoLabel = new Label("Fuzzer - это инструмент для тестирования, позволяющий найти уязвимости в веб-приложениях");
        appInfoLabel.setWrapText(true);
        appInfoLabel.getStyleClass().add("label-background");

        // Контейнер для поля ввода и кнопки
        HBox inputBox = new HBox();
        inputBox.getStyleClass().add("input-box");
        inputBox.setSpacing(10);

        // URL
        TextField urlTextField = new TextField();
        urlTextField.setPromptText("Введите URL адрес");
        urlTextField.getStyleClass().add("text-field");

        Button checkAvailabilityButton = new Button("Проверить доступность");
        checkAvailabilityButton.setMinWidth(160);

        // Устанавливаем обработчик событий для кнопки
        checkAvailabilityButton.setOnAction(event -> {
            String url = urlTextField.getText();
            String statusCode = Fuzzer.sendRequest(url);
            displayResponse(statusCode);
        });

        inputBox.getChildren().addAll(urlTextField, checkAvailabilityButton);

        root.getChildren().addAll(appInfoLabel);

        root.getChildren().addAll(inputBox);

        Scene scene = new Scene(root, 650, 600);
        scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());

        appInfoLabel.getStyleClass().add("label");
        inputBox.getStyleClass().add("input-box");
        urlTextField.getStyleClass().add("text-field");
        checkAvailabilityButton.getStyleClass().add("button");

        primaryStage.setTitle("FuzzerJava");

        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("/icon.jpg")));

        primaryStage.setScene(scene);

        primaryStage.show();
    }

    private void displayResponse(String response) {
        // Окно для отображения ответа
        Stage responseStage = new Stage();
        responseStage.setTitle("HTTP Response");

        Label responseLabel = new Label(response);

        Scene scene = new Scene(responseLabel, 400, 300);
        responseStage.setScene(scene);

        responseStage.show();
    }
    public static void main(String[] args) {
        launch(args);
    }
}
