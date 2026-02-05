public class AnticheatInitializer {
    
    public static QuantumAntiCheatSystem initialize() {
        try {
            // 1. Загрузка конфигурации
            Config config = ConfigLoader.load("anticheat-config.yaml");
            
            // 2. Инициализация ядра
            QuantumAntiCheatSystem anticheat = new QuantumAntiCheatSystem();
            
            // 3. Настройка модулей
            anticheat.configure(config);
            
            // 4. Запуск фоновых процессов
            anticheat.startBackgroundServices();
            
            // 5. Валидация системы
            if (!anticheat.selfTest()) {
                throw new RuntimeException("Self-test failed");
            }
            
            return anticheat;
            
        } catch (Exception e) {
            System.err.println("Failed to initialize anticheat: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
