#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для запуска приложения
"""

import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

print(f"Текущая директория: {current_dir}")
print(f"Файлы в директории: {os.listdir(current_dir)}")

try:
    from app import app, db, Event, User
    from datetime import date, time
    
    print("=== Инициализация приложения ===")
    
    with app.app_context():
        db.create_all()
        print("✓ Таблицы созданы")
        
        event_count = Event.query.count()
        print(f"✓ Событий в базе: {event_count}")
        
        if event_count == 0:
            print("⚠️  Событий нет! Создаем тестовые данные...")
            
            test_events = [
                Event(
                    title='Тестовое событие 1',
                    description='Описание тестового события',
                    date=date.today(),
                    time=time(12, 0),
                    location='Полоцк, ул. Тестовая, 1',
                    latitude=55.485833,
                    longitude=28.758333,
                    category='Тест',
                    interests='["тест", "демо"]',
                    price=10.0,
                    max_participants=50
                ),
                Event(
                    title='Тестовое событие 2',
                    description='Еще одно тестовое событие',
                    date=date.today(),
                    time=time(15, 0),
                    location='Новополоцк, ул. Демо, 2',
                    latitude=55.537797,
                    longitude=28.638198,
                    category='Демо',
                    interests='["демо", "тест"]',
                    price=0.0,
                    max_participants=30
                )
            ]
            
            for event in test_events:
                db.session.add(event)
            
            db.session.commit()
            print("✓ Тестовые события созданы")
        
        print("=== Запуск приложения ===")
        app.run(debug=True, host='0.0.0.0', port=5000)
        
except Exception as e:
    print(f"❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
