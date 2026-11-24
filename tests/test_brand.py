"""Brand-impersonation detection: real legitimate logins must stay clean, kit shapes must not.

The benign fixtures are the title, visible text and identity-provider request paths captured
from live sign-in pages that the earlier text/host matcher flagged as phishing.
"""
import pytest

from luretrace.models import Hop
from luretrace.signals import brand_evidence, detect_brand, evaluate, label_for, total

GSI = ["accounts.google.com/gsi/client", "accounts.google.com/gsi/style",
       "accounts.google.com/gsi/status", "accounts.google.com/gsi/fedcm/listaccounts"]

LEGIT_LOGINS = {
    "dropbox": ("https://www.dropbox.com/login", "Login or Sign Up",
                "Log in or sign up for free\nContinue with Apple\nContinue with Microsoft\nor\n"
                "Email\nContinue\nDropbox\nDesktop app", GSI[:2]),
    "atlassian": ("https://id.atlassian.com/login",
                  "Log in to continue - Log in with Atlassian account",
                  "Log in to continue\nEmail*\nRemember me\nContinue\nPasskey\nGoogle\nMicrosoft\n"
                  "Apple\nSlack\nCan't log in?\nCreate an account", GSI),
    "zoom": ("https://zoom.us/signin", "Sign In | Zoom",
             "Sign in\nEnter email, Zoom Mail or phone number\nNext\nOr sign in with\nSSO\nApple\n"
             "Google\nFacebook\nMicrosoft\nForgot email?\nZoom is protected by reCAPTCHA and the "
             "Google Privacy Policy and Terms of Service apply.", []),
    "notion": ("https://app.notion.com/login", "Notion - Log in",
               "Log in to your Notion account\nEmail\nContinue\nor continue with\nGoogle\nChatGPT\n"
               "Apple\nMicrosoft\nPasskey\nSSO\nNew user? Sign up", GSI),
    "slack": ("https://slack.com/signin", "Login | Slack",
              "Enter your email to sign in\nOr choose another way to sign in.\nSign In With Email\n"
              "OR SIGN IN WITH\nGoogle\nMicrosoft\nApple\nHaving trouble?", []),
    "linkedin": ("https://www.linkedin.com/login/", "LinkedIn Login, Sign in | LinkedIn",
                 "Sign in\nNew to LinkedIn? Join now\nSign in with Microsoft\nSign in with Apple\n"
                 "or\nEmail or phone\nPassword\nForgot password?",
                 ["accounts.google.com/gsi/button", "accounts.google.com/gsi/status"]),
    "box": ("https://app.box.com/login", "Box | Login",
            "Sign Up\nSign In to Your Account\nEmail Address\nNext\nor\nSign in with Google\n"
            "Don't have an account?", []),
}


@pytest.mark.parametrize("name", sorted(LEGIT_LOGINS))
def test_legitimate_saas_logins_are_not_impersonation(name):
    url, title, text, idp = LEGIT_LOGINS[name]
    hop = Hop(0, url, final_url=url, title=title, text_excerpt=text, idp_requests=idp,
              has_email_field=True, has_password_field=True)
    signals = evaluate([hop], True)
    assert not any(s.name == "brand_login_off_domain" for s in signals), brand_evidence(hop, "")
    assert label_for(total(signals)) == "clean"


def _kit(title, text, idp=(), url="https://login.kit-domain.com/", source=""):
    hop = Hop(1, url, final_url=url, title=title, text_excerpt=text, idp_requests=list(idp),
              has_email_field=True, has_password_field=True)
    return hop, source


def test_static_clone_loading_real_microsoft_assets():
    hop, _ = _kit("Sign in to your account", "Sign in\nCan't access your account?",
                  ["aadcdn.msauth.net/shared/1.0/content/js/ConvergedLogin_PCore.js"])
    assert detect_brand(hop, "") == ("Microsoft", "resource")


def test_aitm_proxied_microsoft_page_source_is_decisive():
    # An AiTM proxy serves Microsoft's own page source from the attacker's domain.
    source = '<script>//<![CDATA[\n$Config={"urlGetCredentialType":"https://login.kit-domain.com/x",' \
             '"sCtx":"abc","arrSessions":[]};\n//]]></script>'
    hop, _ = _kit("Sign in to your account", "Sign in")
    assert detect_brand(hop, source) == ("Microsoft", "resource")


def test_cloned_google_login_vs_google_widget():
    clone, _ = _kit("Sign in - Google Accounts", "Sign in\nUse your Google Account\nEmail or phone",
                    ["ssl.gstatic.com/accounts/static/_/js/k=gaia.gaiafe_glif.en.js"])
    assert detect_brand(clone, "") == ("Google", "resource")
    widget_only, _ = _kit("Acme | Log in", "Log in to Acme\nEmail\nPassword", GSI)
    assert detect_brand(widget_only, "") is None


def test_lone_brand_heading_on_a_login_page_is_still_a_clone():
    # The classic kit: Microsoft's title, a "Microsoft" logo line, credential fields.
    hop, _ = _kit("Sign in to your account", "Microsoft\nSign in\nEmail, phone, or Skype")
    assert detect_brand(hop, "") == ("Microsoft", "text")
    # Even without the title, the Microsoft-only flow wording plus the name is enough.
    hop2, _ = _kit("Document Portal", "Microsoft\nCan't access your account?\nNo account? Create one!")
    assert detect_brand(hop2, "") == ("Microsoft", "text")


def test_kit_that_copies_the_real_sso_menu_is_caught_by_its_title():
    # Real Microsoft now shows "Continue with Google/Apple"; kits clone that too.
    hop, _ = _kit("Sign in to your account",
                  "Microsoft\nSign in\nContinue with Google\nContinue with Apple\nNo account? Create one!")
    assert detect_brand(hop, "")[0] == "Microsoft"


def test_merely_naming_a_brand_is_not_impersonation():
    hop, _ = _kit("Acme Calendar - Log in",
                  "Log in\nSync with Microsoft Outlook and Google Calendar\nEmail\nPassword")
    assert detect_brand(hop, "") is None


def test_generic_heading_alone_is_not_enough():
    hop, _ = _kit("Acme | Login", "Sign In to Your Account\nEmail Address\nNext")
    assert detect_brand(hop, "") is None


def test_brand_on_its_own_domain_is_clean():
    url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    hop = Hop(0, url, final_url=url, title="Sign in to your account",
              text_excerpt="Sign in\nCan't access your account?",
              idp_requests=["aadcdn.msauth.net/ests/2.1/content/cdnbundles/x.css"],
              has_email_field=True)
    assert label_for(total(evaluate([hop], True))) == "clean"
