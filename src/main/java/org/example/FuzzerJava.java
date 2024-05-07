package org.example;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class FuzzerJava extends Application {

    @Override
    public void start(Stage primaryStage) {
        VBox root = new VBox();
        root.setSpacing(10);

        // Информация
        Label appInfoLabel = new Label("Fuzzer - это инструмент веб-фаззинга с открытым исходным кодом, разработанный на языке Java.");
        appInfoLabel.setWrapText(true);
        appInfoLabel.getStyleClass().add("label");

        // Контейнер для поля ввода и кнопки
        HBox inputBox = new HBox();
        inputBox.getStyleClass().add("input-box");
        inputBox.setSpacing(10);

        // URL
        TextField urlTextField = new TextField();
        urlTextField.setPromptText("Введите URL адрес");
        urlTextField.getStyleClass().add("text-field");

        Button checkAvailabilityButton = new Button("Проверить доступность");
        checkAvailabilityButton.setMinWidth(150);

        // Устанавливаем обработчик событий для кнопки
        checkAvailabilityButton.setOnAction(event -> {
            String url = urlTextField.getText();
            String statusCode = Fuzzer.sendRequest(url);
            displayResponse(statusCode);
        });

        inputBox.getChildren().addAll(urlTextField, checkAvailabilityButton);

        root.getChildren().addAll(appInfoLabel);

        root.getChildren().addAll(inputBox);

        Scene scene = new Scene(root, 750, 600);

        primaryStage.setTitle("FuzzerJava");

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
