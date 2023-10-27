import os
import requests
import pytest
from app import app
from flask import url_for

@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client

def test_get_home_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Strengthening OS Security from Within' in response.data



