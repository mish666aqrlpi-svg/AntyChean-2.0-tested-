package advanced.anticheat.system;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * БИОМЕТРИЧЕСКИЙ ПРОФИЛЬ ИГРОКА
 */
public class BiometricProfile {
    
    // Мышиные метрики
    private final CircularBuffer<MouseSample> mouseSamples = new CircularBuffer<>(1000);
    private final CircularBuffer<Double> mouseSpeedSamples = new CircularBuffer<>(500);
    private final CircularBuffer<Double> mouseAccelerationSamples = new CircularBuffer<>(500);
    private final CircularBuffer<Double> mouseJerkSamples = new CircularBuffer<>(500);
    
    // Временные метрики кликов
    private final CircularBuffer<ClickSample> clickSamples = new CircularBuffer<>(1000);
    private final CircularBuffer<Double> clickIntervals = new CircularBuffer<>(500);
    private final CircularBuffer<Double> clickDurations = new CircularBuffer<>(500);
    
    // Динамика нажатия клавиш
    private final Map<Integer, KeyStrokeProfile> keystrokeProfiles = new ConcurrentHashMap<>();
    
    // Паттерны движения
    private final CircularBuffer<MovementPattern> movementPatterns = new CircularBuffer<>(100);
    
    // Статистические модели
    private GaussianModel mouseSpeedModel = new GaussianModel();
    private GaussianModel clickIntervalModel = new GaussianModel();
    private GaussianModel[] movementModels = new GaussianModel[10];
    
    // Конструктор
    public BiometricProfile() {
        for (int i = 0; i < movementModels.length; i++) {
            movementModels[i] = new GaussianModel();
        }
    }
    
    public void recordMouseSample(double deltaX, double deltaY, 
                                 long timestamp, double sensitivity) {
        MouseSample sample = new MouseSample(deltaX, deltaY, timestamp, sensitivity);
        mouseSamples.add(sample);
        
        // Расчет скорости
        double speed = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
        mouseSpeedSamples.add(speed);
        mouseSpeedModel.update(speed);
        
        // Обновление других метрик
        updateMouseMetrics(sample);
    }
    
    public void recordClickSample(boolean isLeftClick, int x, int y, 
                                 long downTime, long upTime) {
        ClickSample sample = new ClickSample(isLeftClick, x, y, downTime, upTime);
        clickSamples.add(sample);
        
        // Расчет интервала между кликами
        if (clickSamples.size() > 1) {
            ClickSample prev = clickSamples.get(clickSamples.size() - 2);
            double interval = (sample.downTime - prev.downTime) / 1000.0;
            clickIntervals.add(interval);
            clickIntervalModel.update(interval);
        }
        
        // Расчет длительности клика
        double duration = (sample.upTime - sample.downTime) / 1000.0;
        clickDurations.add(duration);
    }
    
    public void recordKeystroke(int keyCode, long downTime, long upTime) {
        KeyStrokeProfile profile = keystrokeProfiles.computeIfAbsent(keyCode, 
            k -> new KeyStrokeProfile());
        profile.recordStroke(downTime, upTime);
    }
    
    public void recordMovementPattern(double[] pattern, int type) {
        if (type >= 0 && type < movementModels.length) {
            MovementPattern mp = new MovementPattern(pattern, type);
            movementPatterns.add(mp);
            
            // Обновление модели для этого типа движения
            for (int i = 0; i < pattern.length; i++) {
                movementModels[type].update(pattern[i]);
            }
        }
    }
    
    public double calculateDeviation(PlayerQuantumProfile.PlayerStatistics stats) {
        double totalDeviation = 0.0;
        int metricCount = 0;
        
        // Отклонение скорости мыши
        if (mouseSpeedSamples.size() > 10) {
            double currentSpeed = calculateCurrentMouseSpeed();
            double speedDeviation = mouseSpeedModel.calculateDeviation(currentSpeed);
            totalDeviation += speedDeviation;
15:03
metricCount++;
        }
        
        // Отклонение интервалов кликов
        if (clickIntervals.size() > 10) {
            double currentInterval = calculateCurrentClickInterval();
            double intervalDeviation = clickIntervalModel.calculateDeviation(currentInterval);
            totalDeviation += intervalDeviation;
            metricCount++;
        }
        
        // Отклонение паттернов движения
        double movementDeviation = calculateMovementDeviation();
        totalDeviation += movementDeviation;
        metricCount++;
        
        // Отклонение динамики нажатий
        double keystrokeDeviation = calculateKeystrokeDeviation();
        totalDeviation += keystrokeDeviation;
        metricCount++;
        
        return metricCount > 0 ? totalDeviation / metricCount : 0.0;
    }
    
    public double verifyCurrentBehavior(MouseSample currentMouse, 
                                       ClickSample currentClick,
                                       MovementPattern currentMovement) {
        
        double confidence = 1.0;
        
        // Проверка мыши
        confidence *= verifyMouseBehavior(currentMouse);
        
        // Проверка кликов
        confidence *= verifyClickBehavior(currentClick);
        
        // Проверка движения
        confidence *= verifyMovementBehavior(currentMovement);
        
        return confidence;
    }
    
    public Map<String, Object> getBiometricSignature() {
        Map<String, Object> signature = new HashMap<>();
        
        signature.put("mouseSpeedMean", mouseSpeedModel.getMean());
        signature.put("mouseSpeedStd", mouseSpeedModel.getStdDev());
        signature.put("clickIntervalMean", clickIntervalModel.getMean());
        signature.put("clickIntervalStd", clickIntervalModel.getStdDev());
        signature.put("sampleCount", mouseSamples.size());
        
        // Хеш биометрического профиля
        signature.put("profileHash", calculateProfileHash());
        
        return signature;
    }
    
    // Внутренние методы
    private void updateMouseMetrics(MouseSample sample) {
        if (mouseSamples.size() < 2) return;
        
        MouseSample prev = mouseSamples.get(mouseSamples.size() - 2);
        long timeDiff = sample.timestamp - prev.timestamp;
        
        if (timeDiff > 0) {
            double speedPrev = Math.sqrt(prev.deltaX * prev.deltaX + prev.deltaY * prev.deltaY);
            double speedCurr = Math.sqrt(sample.deltaX * sample.deltaX + sample.deltaY * sample.deltaY);
            
            // Ускорение (изменение скорости)
            double acceleration = (speedCurr - speedPrev) / (timeDiff / 1000.0);
            mouseAccelerationSamples.add(acceleration);
            
            // Рывок (изменение ускорения)
            if (mouseAccelerationSamples.size() > 1) {
                double accPrev = mouseAccelerationSamples.get(mouseAccelerationSamples.size() - 2);
                double jerk = (acceleration - accPrev) / (timeDiff / 1000.0);
                mouseJerkSamples.add(jerk);
            }
        }
    }
    
    private double calculateCurrentMouseSpeed() {
        if (mouseSpeedSamples.isEmpty()) return 0.0;
        
        double sum = 0.0;
        int count = Math.min(mouseSpeedSamples.size(), 10);
        
        for (int i = 0; i < count; i++) {
            sum += mouseSpeedSamples.get(mouseSpeedSamples.size() - 1 - i);
        }
        
        return sum / count;
    }
    
    private double calculateCurrentClickInterval() {
        if (clickIntervals.isEmpty()) return 0.0;
        
        double sum = 0.0;
        int count = Math.min(clickIntervals.size(), 10);
        
        for (int i = 0; i < count; i++) {
            sum += clickIntervals.get(clickIntervals.size() - 1 - i);
        }
        
        return sum / count;
    }
    
    private double calculateMovementDeviation() {
        if (movementPatterns.isEmpty()) return 0.0;
15:03
double totalDeviation = 0.0;
        int count = 0;
        
        for (int i = 0; i < movementPatterns.size(); i++) {
            MovementPattern pattern = movementPatterns.get(i);
            GaussianModel model = movementModels[pattern.type];
            
            for (double value : pattern.pattern) {
                totalDeviation += model.calculateDeviation(value);
                count++;
            }
        }
        
        return count > 0 ? totalDeviation / count : 0.0;
    }
    
    private double calculateKeystrokeDeviation() {
        if (keystrokeProfiles.isEmpty()) return 0.0;
        
        double totalDeviation = 0.0;
        int count = 0;
        
        for (KeyStrokeProfile profile : keystrokeProfiles.values()) {
            totalDeviation += profile.calculateDeviation();
            count++;
        }
        
        return count > 0 ? totalDeviation / count : 0.0;
    }
    
    private double verifyMouseBehavior(MouseSample sample) {
        if (mouseSpeedSamples.size() < 10) return 0.5;
        
        double speed = Math.sqrt(sample.deltaX * sample.deltaX + sample.deltaY * sample.deltaY);
        double deviation = mouseSpeedModel.calculateDeviation(speed);
        
        // Чем больше отклонение, тем меньше уверенность
        return Math.exp(-deviation * deviation);
    }
    
    private double verifyClickBehavior(ClickSample sample) {
        if (clickIntervals.size() < 10) return 0.5;
        
        // Здесь должна быть логика проверки паттерна кликов
        return 0.8; // Заглушка
    }
    
    private double verifyMovementBehavior(MovementPattern pattern) {
        if (pattern == null) return 0.5;
        
        GaussianModel model = movementModels[pattern.type];
        double totalDeviation = 0.0;
        
        for (double value : pattern.pattern) {
            totalDeviation += model.calculateDeviation(value);
        }
        
        double avgDeviation = totalDeviation / pattern.pattern.length;
        return Math.exp(-avgDeviation * avgDeviation);
    }
    
    private String calculateProfileHash() {
        // Создание хеша на основе всех биометрических данных
        StringBuilder sb = new StringBuilder();
        
        sb.append(mouseSpeedModel.getMean());
        sb.append(clickIntervalModel.getMean());
        sb.append(mouseSamples.size());
        sb.append(clickSamples.size());
        
        // Простой хеш для примера
        return Integer.toHexString(sb.toString().hashCode());
    }
    
    // Вложенные классы
    public static class MouseSample {
        public final double deltaX;
        public final double deltaY;
        public final long timestamp;
        public final double sensitivity;
        
        public MouseSample(double deltaX, double deltaY, long timestamp, double sensitivity) {
            this.deltaX = deltaX;
            this.deltaY = deltaY;
            this.timestamp = timestamp;
            this.sensitivity = sensitivity;
        }
    }
    
    public static class ClickSample {
        public final boolean isLeftClick;
        public final int x, y;
        public final long downTime, upTime;
        
        public ClickSample(boolean isLeftClick, int x, int y, long downTime, long upTime) {
            this.isLeftClick = isLeftClick;
            this.x = x;
            this.y = y;
            this.downTime = downTime;
            this.upTime = upTime;
        }
    }
    
    public static class KeyStrokeProfile {
        private final CircularBuffer<Double> durations = new CircularBuffer<>(100);
        private final GaussianModel durationModel = new GaussianModel();
        
        public void recordStroke(long downTime, long upTime) {
            double duration = (upTime - downTime) / 1000.0;
            durations.add(duration);
            durationModel.update(duration);
        }
        
        public double calculateDeviation() {
            if (durations.isEmpty()) return 0.0;
15:03
double current = durations.get(durations.size() - 1);
            return durationModel.calculateDeviation(current);
        }
    }
    
    public static class MovementPattern {
        public final double[] pattern;
        public final int type; // 0-9: разные типы движения
        
        public MovementPattern(double[] pattern, int type) {
            this.pattern = pattern.clone();
            this.type = type;
        }
    }
    
    public static class GaussianModel {
        private double mean = 0.0;
        private double m2 = 0.0;
        private int count = 0;
        
        public void update(double value) {
            count++;
            double delta = value - mean;
            mean += delta / count;
            double delta2 = value - mean;
            m2 += delta * delta2;
        }
        
        public double getMean() { return mean; }
        
        public double getVariance() {
            return count > 1 ? m2 / (count - 1) : 0.0;
        }
        
        public double getStdDev() {
            return Math.sqrt(getVariance());
        }
        
        public double calculateDeviation(double value) {
            if (count < 2) return 0.0;
            
            double stdDev = getStdDev();
            if (stdDev == 0.0) return 0.0;
            
            return Math.abs((value - mean) / stdDev);
        }
    }
    
    public static class CircularBuffer<T> {
        private final T[] buffer;
        private int head = 0;
        private int size = 0;
        
        @SuppressWarnings("unchecked")
        public CircularBuffer(int capacity) {
            this.buffer = (T[]) new Object[capacity];
        }
        
        public synchronized void add(T item) {
            buffer[head] = item;
            head = (head + 1) % buffer.length;
            if (size < buffer.length) {
                size++;
            }
        }
        
        public synchronized T get(int index) {
            if (index < 0 || index >= size) {
                throw new IndexOutOfBoundsException();
            }
            int actualIndex = (head - size + index + buffer.length) % buffer.length;
            return buffer[actualIndex];
        }
        
        public synchronized int size() {
            return size;
        }
        
        public synchronized boolean isEmpty() {
            return size == 0;
        }
        
        public synchronized T[] toArray(T[] array) {
            for (int i = 0; i < size; i++) {
                array[i] = get(i);
            }
            return array;
        }
    }
}
