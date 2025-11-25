#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тестовый скрипт для проверки работы приложения
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db, Event, User
    from datetime import date, time
    
    print("=== Тестирование приложения ===")
    
    with app.app_context():
        db.create_all()
        print("✓ Таблицы созданы")
        
        event_count = Event.query.count()
        print(f"✓ Событий в базе: {event_count}")
        
        user_count = User.query.count()
        print(f"✓ Пользователей в базе: {user_count}")
        
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
            
            event_count = Event.query.count()
            print(f"✓ Событий после создания: {event_count}")
        
        events = Event.query.limit(3).all()
        print("\n=== Первые события ===")
        for i, event in enumerate(events, 1):
            print(f"{i}. {event.title}")
            print(f"   Место: {event.location}")
            print(f"   Координаты: {event.latitude}, {event.longitude}")
            print(f"   Цена: {event.price} BYN")
            print()
        
        print("=== Тест завершен успешно ===")
        
except Exception as e:
    print(f"❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
