import pytest
from unittest.mock import patch, MagicMock
from core.heuristics import *

def test_punycode():
    h = PunycodeHomographHeuristic()
    assert h.check("http://xn--pypal-4ve.com").triggered == True
    assert h.check("http://paypal.com").triggered == False

@patch('core.heuristics.requests.get')
def test_redirect_chain(mock_get):
    h = RedirectChainHeuristic()
    
    # Mock Positive Case
    mock_resp_1 = MagicMock(url="http://short.ly")
    mock_resp_final = MagicMock(url="http://evil.com/login")
    mock_resp_final.history = [mock_resp_1]
    mock_get.return_value = mock_resp_final
    
    res = h.check("http://short.ly")
    assert res.triggered == True
    assert "evil.com" in res.evidence

    # Mock Negative Case
    mock_resp_safe = MagicMock(url="http://safe.com")
    mock_resp_safe.history = []
    mock_get.return_value = mock_resp_safe
    assert h.check("http://safe.com").triggered == False

@patch('core.heuristics.whois.whois')
def test_newly_registered(mock_whois):
    h = NewlyRegisteredDomainHeuristic()
    
    # Mock Positive (10 days old)
    mock_whois.return_value = MagicMock(creation_date=datetime.datetime.now() - datetime.timedelta(days=10))
    assert h.check("http://new-domain.com").triggered == True
    
    # Mock Negative (100 days old)
    mock_whois.return_value = MagicMock(creation_date=datetime.datetime.now() - datetime.timedelta(days=100))
    assert h.check("http://old-domain.com").triggered == False

def test_lookalike():
    h = LookalikeCharHeuristic()
    assert h.check("http://g00gle.com").triggered == True
    assert h.check("http://google.com").triggered == False

def test_path_depth():
    h = ExcessivePathDepthHeuristic()
    assert h.check("http://site.com/a/b/c/d/e/f/g").triggered == True
    assert h.check("http://site.com/about/team").triggered == False