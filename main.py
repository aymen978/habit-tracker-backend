"""
Habit Tracker Backend – mit Nutzer-Login und Kategorien
----------------------------------------------------------
FastAPI + SQLModel (SQLite) + JWT-Login.

Starten:
    pip install -r requirements.txt
    uvicorn main:app --reload

API-Doku: http://127.0.0.1:8000/docs
"""

from datetime import date, datetime, timedelta
from typing import Optional, List
import os
import json
import random
import secrets
import smtplib
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, create_engine, Session, select
from passlib.context import CryptContext
from jose import JWTError, jwt
import firebase_admin
from firebase_admin import credentials, messaging
from apscheduler.schedulers.background import BackgroundScheduler

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------

# WICHTIG: In Produktion wird SECRET_KEY als Umgebungsvariable gesetzt
# (z.B. bei Railway/Render in den Projekt-Einstellungen), NIEMALS fest im
# Code, weil der Code z.B. auf GitHub öffentlich sichtbar sein könnte.
# Der zweite Wert hier ist nur ein Rückfallwert für lokale Entwicklung.
SECRET_KEY = os.environ.get("SECRET_KEY", "nur-fuers-lernen-aendere-das-in-produktion-unbedingt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # Token 7 Tage gültig

# WICHTIG: Beim Hosting (z.B. Railway) wird DATABASE_URL automatisch als
# Umgebungsvariable gesetzt und zeigt auf eine echte PostgreSQL-Datenbank
# (die Daten dauerhaft speichert). Lokal, wenn diese Variable fehlt, nutzen
# wir stattdessen die einfache SQLite-Datei wie bisher.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./habits.db")
# Manche Hosting-Dienste liefern "postgres://", SQLAlchemy braucht aber
# "postgresql://" - hier automatisch korrigiert, falls nötig.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, echo=False, connect_args=_connect_args)

# Erlaubte Herkunfts-Adressen für Anfragen (CORS). In Produktion sollte hier
# NICHT "*" stehen, sondern die genaue Domain deiner App/Website. Über die
# Umgebungsvariable CORS_ORIGINS (Komma-getrennt) einstellbar.
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def get_session():
    with Session(engine) as session:
        yield session


# ---------------------------------------------------------------------------
# Kategorien, die die App anbietet (fest definiert, einfach zu erweitern)
# ---------------------------------------------------------------------------

CATEGORIES = {
    "health": {"label": "Gesundheit", "icon": "favorite", "color": "#E85D75"},
    "learning": {"label": "Lernen", "icon": "school", "color": "#3D7BFD"},
    "fitness": {"label": "Fitness", "icon": "fitness_center", "color": "#FF8C42"},
    "mindfulness": {"label": "Achtsamkeit", "icon": "self_improvement", "color": "#6C5CE7"},
    "productivity": {"label": "Produktivität", "icon": "task_alt", "color": "#00B894"},
    "social": {"label": "Sozial", "icon": "groups", "color": "#FDA7DF"},
    "other": {"label": "Sonstiges", "icon": "star", "color": "#95A5A6"},
}

# ---------------------------------------------------------------------------
# Datenmodelle
# ---------------------------------------------------------------------------

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    points: int = 0
    total_completions: int = 0
    streak_freezes_available: int = 1
    freezes_used_count: int = 0
    last_freeze_refill: date = Field(default_factory=date.today)
    total_habits_created: int = 0  # Lifetime-Zähler, sinkt nicht beim Löschen (für "Zielstrebig")
    last_all_done_bonus_date: Optional[date] = None  # verhindert Mehrfach-Bonus am selben Tag
    # Push-Token des Geräts (von Firebase Cloud Messaging). Wird beim App-Start
    # gesetzt/aktualisiert. None = Nutzer hat sich noch nie mit Push-Empfang
    # angemeldet (z.B. alte App-Version, oder Berechtigung abgelehnt).
    fcm_token: Optional[str] = None
    # Sprache für automatisch generierte Texte (Insights). Die App speichert
    # die Sprachwahl bisher nur lokal auf dem Gerät - der Server braucht sie
    # separat, um serverseitig generierte Texte in der richtigen Sprache zu
    # erstellen. "de" als Standard, da das die App-Standardsprache ist.
    preferred_language: str = "de"
    # Zuletzt generierter Wochenrückblick-Text (siehe _generate_weekly_insights).
    latest_insight: Optional[str] = None
    latest_insight_generated_at: Optional[date] = None


class UserCreate(SQLModel):
    username: str
    email: str
    password: str


class PasswordResetToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    token: str = Field(unique=True, index=True)
    expires_at: datetime
    used: bool = False


class Habit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    title: str
    category: str = "other"
    icon: Optional[str] = None  # z.B. "fitness_center". None = Kategorie-Icon verwenden
    color: Optional[str] = None  # Hex-Code z.B. "#8B5CF6". None = Kategorie-Farbe verwenden
    notes: Optional[str] = None  # Freitext-Notiz des Nutzers zu diesem Habit
    reminder_time: Optional[str] = None  # Format "HH:MM", z.B. "08:30". None = keine Erinnerung
    # Komma-getrennte Wochentage, an denen das Habit ansteht (1=Montag..7=Sonntag).
    # Leer/None = jeden Tag (Standard-Verhalten wie bisher).
    active_weekdays: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    current_streak: int = 0
    best_streak: int = 0
    last_completed: Optional[date] = None


class HabitCreate(SQLModel):
    title: str
    category: str = "other"
    icon: Optional[str] = None
    color: Optional[str] = None
    notes: Optional[str] = None
    reminder_time: Optional[str] = None
    active_weekdays: Optional[List[int]] = None


class HabitRead(SQLModel):
    id: int
    title: str
    category: str
    icon: Optional[str]
    color: Optional[str]
    notes: Optional[str] = None
    reminder_time: Optional[str]
    active_weekdays: Optional[List[int]]
    current_streak: int
    best_streak: int
    last_completed: Optional[date]
    completed_today: bool = False


class HabitLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    habit_id: int = Field(foreign_key="habit.id", index=True)
    completed_on: date
    completed_at: Optional[datetime] = None  # exakte Uhrzeit, für "Früher Vogel"/"Nachtmensch"


class PointsLog(SQLModel, table=True):
    """Protokolliert jede einzelne Punktegutschrift mit Datum, damit wir
    später den XP-Verlauf über Zeit (z.B. pro Wochentag) anzeigen können."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    points: int
    earned_on: date


class Category(SQLModel, table=True):
    """Eigene, vom Nutzer angelegte Kategorien (zusätzlich zu den fest
    eingebauten CATEGORIES oben). Jede gehört genau einem Nutzer."""
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    key: str = Field(index=True)  # z.B. "custom_3" - intern eindeutig
    label: str
    icon: str = "star"
    color: str = "#95A5A6"


class CategoryCreate(SQLModel):
    label: str
    icon: str = "star"
    color: str = "#95A5A6"


class CategoryOut(SQLModel):
    key: str
    label: str
    icon: str
    color: str
    custom: bool = False


# ---------------------------------------------------------------------------
# Sicherheits-Hilfsfunktionen
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Anmeldedaten ungültig oder abgelaufen",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise credentials_exception
    return user


# ---------------------------------------------------------------------------
# App-Setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Habit Tracker API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Push-Benachrichtigungen (Firebase Cloud Messaging)
# ---------------------------------------------------------------------------
# Die Dienstkonto-Zugangsdaten kommen als kompletter JSON-Inhalt aus der
# Umgebungsvariable FIREBASE_CREDENTIALS_JSON (bei Railway unter
# "Variables" eintragen - kompletten Inhalt der heruntergeladenen
# Firebase-Schlüsseldatei reinkopieren). Läuft nichts, wenn die Variable
# fehlt (z.B. lokal beim Testen), damit die App trotzdem startet.
_firebase_ready = False
_raw_firebase_creds = os.environ.get("FIREBASE_CREDENTIALS_JSON")
if _raw_firebase_creds:
    try:
        cred = credentials.Certificate(json.loads(_raw_firebase_creds))
        firebase_admin.initialize_app(cred)
        _firebase_ready = True
    except Exception as exc:  # noqa: BLE001 - beim Start nur loggen, nicht abstürzen
        print(f"Firebase-Initialisierung fehlgeschlagen: {exc}")


def _send_push(token: str, title: str, body: str) -> bool:
    """Verschickt eine einzelne Push-Benachrichtigung. Gibt False zurück
    (statt einen Fehler zu werfen), falls Firebase nicht eingerichtet ist
    oder der Versand fehlschlägt (z.B. Token ungültig/App deinstalliert)."""
    if not _firebase_ready or not token:
        return False
    try:
        messaging.send(
            messaging.Message(
                token=token,
                notification=messaging.Notification(title=title, body=body),
                android=messaging.AndroidConfig(priority="high"),
            )
        )
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"Push-Versand fehlgeschlagen: {exc}")
        return False


# Gleiche Zeitzone wie bisher in der App (Europe/Berlin) - wichtig, weil
# Railway-Server standardmäßig in UTC laufen.
_BERLIN_TZ = ZoneInfo("Europe/Berlin")
# Merkt sich pro Minute, welche Habit-IDs schon benachrichtigt wurden, damit
# bei überlappenden Job-Läufen keine Doppel-Push verschickt wird. Wird
# einfach im Arbeitsspeicher gehalten - reicht für diesen Zweck völlig.
_already_notified_this_minute: set[tuple[int, str]] = set()


def _check_and_send_reminders():
    """Läuft jede Minute: sucht alle Habits, deren Erinnerungszeit genau
    jetzt ist, und schickt eine Push-Benachrichtigung an den Besitzer."""
    now = datetime.now(_BERLIN_TZ)
    current_hhmm = now.strftime("%H:%M")
    minute_key = now.strftime("%Y-%m-%d %H:%M")

    with Session(engine) as session:
        habits = session.exec(
            select(Habit).where(Habit.reminder_time == current_hhmm)
        ).all()
        for habit in habits:
            dedupe_key = (habit.id, minute_key)
            if dedupe_key in _already_notified_this_minute:
                continue
            user = session.get(User, habit.user_id)
            if user is None or not user.fcm_token:
                continue
            sent = _send_push(
                user.fcm_token,
                f"Zeit für: {habit.title}",
                "Nicht vergessen – trag dir den Erfolg heute ein! 🔥",
            )
            if sent:
                _already_notified_this_minute.add(dedupe_key)

    # Aufräumen: alte Minuten-Einträge nicht ewig behalten (Speicher sparen).
    if len(_already_notified_this_minute) > 500:
        _already_notified_this_minute.clear()


scheduler = BackgroundScheduler(timezone=str(_BERLIN_TZ))
scheduler.add_job(_check_and_send_reminders, "interval", seconds=60, id="reminder_check")


# ---------------------------------------------------------------------------
# Wochenrückblick / "Insights" - KEIN echtes KI-Modell, sondern echte
# Datenbank-Auswertung + eine Bibliothek vorformulierter Textvarianten.
# Bewusste Design-Entscheidung: kleine Sprachmodelle sind bei echter
# Statistik unzuverlässig, deshalb übernimmt Python die Analyse und wählt
# nur passend aus vorgeschriebenen, mehrsprachigen Textbausteinen aus.
# ---------------------------------------------------------------------------

_INSIGHT_TEMPLATES = {
    "de": {
        "perfect_week": [
            "Perfekte Woche! Du hast alle deine Habits an jedem geplanten Tag geschafft. 🏆",
            "Makellos! 100% diese Woche – besser geht's nicht. 🔥",
        ],
        "trend_up": [
            "Starke Woche! Deine Abschlussrate ist von {prev}% auf {curr}% gestiegen. 📈",
            "Aufwärtstrend: {curr}% diese Woche, {prev}% letzte Woche – weiter so!",
        ],
        "trend_down": [
            "Diese Woche lief's etwas ruhiger ({curr}% statt {prev}%) – kein Problem, nächste Woche geht's weiter.",
            "Von {prev}% auf {curr}% – jeder hat mal eine schwächere Woche. Dranbleiben zählt.",
        ],
        "weekday_pattern": [
            "{weekday} scheinen bei dir schwieriger zu sein als andere Tage – vielleicht hilft eine Erinnerung zu einer anderen Uhrzeit?",
            "Auffällig: An {weekday} hakst du am seltensten ab. Wert, mal drüber nachzudenken.",
        ],
        "streak_highlight": [
            "Dein Streak bei „{habit}“ steht bei {streak} Tagen – stark!",
            "{streak} Tage am Stück bei „{habit}“ – beeindruckend.",
        ],
        "default": [
            "Du bist dabei – jeder abgehakte Tag zählt. Weiter so!",
            "Kontinuität schlägt Perfektion. Mach einfach weiter.",
        ],
    },
    "en": {
        "perfect_week": [
            "Perfect week! You completed every scheduled habit every day. 🏆",
            "Flawless – 100% this week. Can't do better than that. 🔥",
        ],
        "trend_up": [
            "Great week! Your completion rate went from {prev}% to {curr}%. 📈",
            "Trending up: {curr}% this week vs {prev}% last week – keep it up!",
        ],
        "trend_down": [
            "A quieter week ({curr}% vs {prev}%) – no worries, next week's a fresh start.",
            "From {prev}% to {curr}% – everyone has an off week. Showing up is what counts.",
        ],
        "weekday_pattern": [
            "{weekday}s seem tougher for you than other days – maybe a different reminder time would help?",
            "Noticed: you complete habits least often on {weekday}s. Worth a thought.",
        ],
        "streak_highlight": [
            "Your streak on \"{habit}\" is at {streak} days – strong!",
            "{streak} days in a row on \"{habit}\" – impressive.",
        ],
        "default": [
            "You're showing up – every completed day counts. Keep going!",
            "Consistency beats perfection. Just keep going.",
        ],
    },
}

_WEEKDAY_NAMES = {
    "de": ["Montage", "Dienstage", "Mittwoche", "Donnerstage", "Freitage", "Samstage", "Sonntage"],
    "en": ["Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays", "Sundays"],
}


def _possible_days_for_habit(habit: "Habit", start: date, end: date) -> int:
    """Zählt, an wie vielen Tagen im Zeitraum dieses Habit überhaupt fällig
    war (berücksichtigt Erstelldatum und feste Wochentage, falls gesetzt)."""
    active_days = None
    if habit.active_weekdays:
        active_days = {int(x) for x in habit.active_weekdays.split(",") if x}
    count = 0
    d = max(start, habit.created_at.date())
    while d <= end:
        if active_days is None or d.isoweekday() in active_days:
            count += 1
        d += timedelta(days=1)
    return count


def _generate_insight_for_user(user: "User", session: Session) -> Optional[str]:
    lang = user.preferred_language if user.preferred_language in ("de", "en") else "en"
    templates = _INSIGHT_TEMPLATES[lang]
    weekday_names = _WEEKDAY_NAMES[lang]

    today = date.today()
    week_start = today - timedelta(days=6)
    prev_week_start = week_start - timedelta(days=7)
    prev_week_end = week_start - timedelta(days=1)

    habits = session.exec(select(Habit).where(Habit.user_id == user.id)).all()
    if not habits:
        return None
    habit_ids = [h.id for h in habits]

    logs_this_week = session.exec(
        select(HabitLog).where(
            HabitLog.habit_id.in_(habit_ids),
            HabitLog.completed_on >= week_start,
            HabitLog.completed_on <= today,
        )
    ).all()
    logs_prev_week = session.exec(
        select(HabitLog).where(
            HabitLog.habit_id.in_(habit_ids),
            HabitLog.completed_on >= prev_week_start,
            HabitLog.completed_on <= prev_week_end,
        )
    ).all()

    possible_this = sum(_possible_days_for_habit(h, week_start, today) for h in habits)
    possible_prev = sum(_possible_days_for_habit(h, prev_week_start, prev_week_end) for h in habits)
    rate_this = round((len(logs_this_week) / possible_this) * 100) if possible_this else 0
    rate_prev = round((len(logs_prev_week) / possible_prev) * 100) if possible_prev else None

    # Wochentag mit den wenigsten Abschlüssen finden (nur relevant, wenn
    # genug Daten da sind und es einen klaren "schwächsten" Tag gibt).
    weekday_counts = [0] * 7  # Index 0 = Montag
    for log in logs_this_week:
        weekday_counts[log.completed_on.isoweekday() - 1] += 1
    weakest_weekday = None
    if sum(weekday_counts) >= 4:  # nur bei ausreichend Datenpunkten werten
        min_count = min(weekday_counts)
        max_count = max(weekday_counts)
        if max_count > 0 and min_count < max_count:
            weakest_weekday = weekday_counts.index(min_count)

    best_habit = max(habits, key=lambda h: h.current_streak, default=None)
    best_streak = best_habit.current_streak if best_habit else 0

    # Auswahl-Priorität: das auffälligste/positivste Muster gewinnt.
    category = "default"
    if possible_this > 0 and len(logs_this_week) >= possible_this:
        category = "perfect_week"
    elif best_streak >= 7:
        category = "streak_highlight"
    elif rate_prev is not None and rate_this - rate_prev >= 10:
        category = "trend_up"
    elif rate_prev is not None and rate_prev - rate_this >= 10:
        category = "trend_down"
    elif weakest_weekday is not None:
        category = "weekday_pattern"

    text = random.choice(templates[category])
    return text.format(
        curr=rate_this,
        prev=rate_prev if rate_prev is not None else rate_this,
        habit=best_habit.title if best_habit else "",
        streak=best_streak,
        weekday=weekday_names[weakest_weekday] if weakest_weekday is not None else "",
    )


def _generate_weekly_insights():
    """Läuft einmal täglich: prüft pro Nutzer, ob der letzte Wochenrückblick
    7+ Tage her ist (oder noch nie erstellt wurde), und generiert ggf. einen
    neuen."""
    today = date.today()
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        for user in users:
            needs_generation = (
                user.latest_insight_generated_at is None
                or (today - user.latest_insight_generated_at).days >= 7
            )
            if not needs_generation:
                continue
            text = _generate_insight_for_user(user, session)
            if text:
                user.latest_insight = text
                user.latest_insight_generated_at = today
                session.add(user)
        session.commit()


scheduler.add_job(
    _generate_weekly_insights, "cron", hour=6, minute=0, id="weekly_insights"
)


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    if not scheduler.running:
        scheduler.start()


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _to_read_model(habit: Habit) -> HabitRead:
    return HabitRead(
        id=habit.id,
        title=habit.title,
        category=habit.category,
        icon=habit.icon,
        color=habit.color,
        notes=habit.notes,
        reminder_time=habit.reminder_time,
        active_weekdays=_parse_weekdays(habit.active_weekdays),
        current_streak=habit.current_streak,
        best_streak=habit.best_streak,
        last_completed=habit.last_completed,
        completed_today=(habit.last_completed == date.today()),
    )


def _parse_weekdays(value: Optional[str]) -> Optional[List[int]]:
    if not value:
        return None
    return [int(v) for v in value.split(",") if v]


def _weekdays_to_str(weekdays: Optional[List[int]]) -> Optional[str]:
    if not weekdays:
        return None
    return ",".join(str(w) for w in sorted(set(weekdays)))


def _previous_scheduled_day(weekdays: Optional[List[int]], from_date: date) -> date:
    """Findet den letzten Tag VOR from_date, der zum Zeitplan des Habits passt.
    Bei täglichen Habits (weekdays=None) ist das einfach 'gestern'. Bei z.B.
    Mo/Mi/Fr wird rückwärts gesucht, bis ein passender Wochentag gefunden wird."""
    candidate = from_date - timedelta(days=1)
    if not weekdays:
        return candidate
    for _ in range(8):  # maximal eine volle Woche zurücksuchen
        if candidate.isoweekday() in weekdays:
            return candidate
        candidate -= timedelta(days=1)
    return candidate


# Punkte, die für jede Level-Stufe nötig sind, wächst leicht mit jedem Level
# (Level 1: 0-99 Punkte, Level 2: 100-249, Level 3: 250-449, usw.)
def _compute_level(points: int) -> dict:
    level = 1
    points_for_next = 100
    threshold = 0
    while points >= threshold + points_for_next:
        threshold += points_for_next
        level += 1
        points_for_next += 50  # jedes Level braucht etwas mehr Punkte als das davor

    points_into_level = points - threshold
    return {
        "level": level,
        "points_into_level": points_into_level,
        "points_needed_for_next_level": points_for_next,
    }


def _maybe_refill_streak_freeze(user: User) -> None:
    """Füllt einmal pro Woche automatisch einen Streak-Freeze auf (max. 1 verfügbar)."""
    days_since_refill = (date.today() - user.last_freeze_refill).days
    if days_since_refill >= 7 and user.streak_freezes_available < 1:
        user.streak_freezes_available = 1
        user.last_freeze_refill = date.today()


# ---------------------------------------------------------------------------
# Auth-Endpunkte
# ---------------------------------------------------------------------------

def _send_email(to_address: str, subject: str, body: str) -> bool:
    """Versucht eine E-Mail per SMTP zu versenden. Braucht die Umgebungs-
    variablen SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM.
    Sind sie nicht gesetzt (z.B. lokal beim Entwickeln), wird die E-Mail
    stattdessen einfach ins Server-Log geschrieben - so kannst du die
    Funktion testen, ohne einen echten Mail-Anbieter einzurichten."""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from = os.environ.get("SMTP_FROM", smtp_user)

    if not all([smtp_host, smtp_port, smtp_user, smtp_password]):
        print(f"[E-Mail nicht gesendet, SMTP nicht konfiguriert] An: {to_address}\n"
              f"Betreff: {subject}\n{body}")
        return False

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to_address

        with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_address], msg.as_string())
        return True
    except Exception as e:
        print(f"[E-Mail-Versand fehlgeschlagen] {e}")
        return False


@app.post("/auth/register", response_model=dict)
def register(data: UserCreate, session: Session = Depends(get_session)):
    existing_username = session.exec(select(User).where(User.username == data.username)).first()
    if existing_username:
        raise HTTPException(status_code=400, detail="Nutzername bereits vergeben")

    existing_email = session.exec(select(User).where(User.email == data.email)).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="E-Mail-Adresse bereits registriert")

    user = User(username=data.username, email=data.email, hashed_password=hash_password(data.password))
    session.add(user)
    session.commit()
    session.refresh(user)

    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "username": user.username}


@app.post("/auth/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nutzername oder Passwort falsch",
        )

    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "username": user.username}


class ForgotPasswordRequest(SQLModel):
    email: str


class ResetPasswordRequest(SQLModel):
    token: str
    new_password: str


@app.post("/auth/forgot-password")
def forgot_password(data: ForgotPasswordRequest, session: Session = Depends(get_session)):
    """Fordert einen Passwort-Reset-Code an. Gibt IMMER eine generische
    Erfolgsmeldung zurück (auch wenn die E-Mail nicht existiert) - so kann
    niemand herausfinden, welche E-Mail-Adressen bei uns registriert sind."""
    user = session.exec(select(User).where(User.email == data.email)).first()

    if user:
        # Alten, noch gültigen Reset-Code für diesen Nutzer entwerten
        old_tokens = session.exec(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id, PasswordResetToken.used == False
            )
        ).all()
        for t in old_tokens:
            t.used = True
            session.add(t)

        reset_token = secrets.token_hex(4).upper()  # kurzer 8-stelliger Code, leicht abtippbar
        expires = datetime.utcnow() + timedelta(minutes=30)
        session.add(PasswordResetToken(user_id=user.id, token=reset_token, expires_at=expires))
        session.commit()

        _send_email(
            user.email,
            "Dein Passwort-Reset-Code",
            f"Hallo {user.username},\n\n"
            f"Dein Code zum Zurücksetzen deines Passworts lautet:\n\n{reset_token}\n\n"
            f"Der Code ist 30 Minuten gültig. Falls du das nicht angefordert hast, "
            f"kannst du diese E-Mail ignorieren.",
        )

    return {"message": "Falls die E-Mail-Adresse registriert ist, wurde ein Code verschickt."}


@app.post("/auth/reset-password")
def reset_password(data: ResetPasswordRequest, session: Session = Depends(get_session)):
    reset_entry = session.exec(
        select(PasswordResetToken).where(PasswordResetToken.token == data.token.upper())
    ).first()

    if not reset_entry or reset_entry.used or reset_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code ungültig oder abgelaufen")

    user = session.get(User, reset_entry.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Code ungültig oder abgelaufen")

    user.hashed_password = hash_password(data.new_password)
    reset_entry.used = True
    session.add(user)
    session.add(reset_entry)
    session.commit()

    return {"message": "Passwort erfolgreich geändert"}


@app.get("/auth/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username}


class FcmTokenUpdate(SQLModel):
    token: str


@app.post("/users/me/fcm-token")
def update_fcm_token(
    data: FcmTokenUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Speichert/aktualisiert den Push-Token des aktuellen Geräts. Wird von
    der App bei jedem Start aufgerufen (Token kann sich ändern, z.B. nach
    Neuinstallation)."""
    current_user.fcm_token = data.token
    session.add(current_user)
    session.commit()
    return {"message": "Push-Token gespeichert"}


class LanguageUpdate(SQLModel):
    language: str


@app.post("/users/me/language")
def update_preferred_language(
    data: LanguageUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Speichert die App-Sprache des Nutzers auf dem Server - nötig, damit
    serverseitig generierte Texte (Insights) in der richtigen Sprache
    erstellt werden."""
    current_user.preferred_language = data.language
    session.add(current_user)
    session.commit()
    return {"message": "Sprache gespeichert"}


@app.get("/insights/latest")
def get_latest_insight(current_user: User = Depends(get_current_user)):
    """Gibt den zuletzt generierten Wochenrückblick zurück, falls vorhanden."""
    return {
        "message": current_user.latest_insight,
        "generated_at": current_user.latest_insight_generated_at,
    }


@app.post("/insights/generate-now")
def generate_insight_now(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """TEMPORÄR zum Testen: erzeugt sofort einen neuen Wochenrückblick,
    ohne auf den täglichen 6-Uhr-Hintergrund-Job zu warten. Vor der
    Veröffentlichung wieder entfernen (siehe reminders_screen.dart-Vorbild)."""
    text = _generate_insight_for_user(current_user, session)
    if text is None:
        raise HTTPException(
            status_code=400,
            detail="Noch keine Habits vorhanden - lege mindestens ein Habit an, bevor du testest.",
        )
    current_user.latest_insight = text
    current_user.latest_insight_generated_at = date.today()
    session.add(current_user)
    session.commit()
    return {"message": current_user.latest_insight, "generated_at": current_user.latest_insight_generated_at}


# ---------------------------------------------------------------------------
# Kategorien-Endpunkte (feste Kategorien + eigene, pro Nutzer anlegbare)
# ---------------------------------------------------------------------------

@app.get("/categories", response_model=List[CategoryOut])
def list_categories(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    result = [
        CategoryOut(key=key, label=info["label"], icon=info["icon"], color=info["color"], custom=False)
        for key, info in CATEGORIES.items()
    ]
    own = session.exec(select(Category).where(Category.user_id == current_user.id)).all()
    result += [
        CategoryOut(key=c.key, label=c.label, icon=c.icon, color=c.color, custom=True) for c in own
    ]
    return result


@app.post("/categories", response_model=CategoryOut)
def create_category(
    data: CategoryCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    label = data.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="Name darf nicht leer sein")
    # eindeutigen internen Key erzeugen (z.B. "custom_7")
    existing_count = session.exec(
        select(Category).where(Category.user_id == current_user.id)
    ).all()
    key = f"custom_{current_user.id}_{len(existing_count) + 1}_{secrets.token_hex(2)}"
    category = Category(user_id=current_user.id, key=key, label=label, icon=data.icon, color=data.color)
    session.add(category)
    session.commit()
    session.refresh(category)
    return CategoryOut(key=category.key, label=category.label, icon=category.icon, color=category.color, custom=True)


def _get_owned_category(key: str, session: Session, current_user: User) -> Category:
    category = session.exec(
        select(Category).where(Category.key == key, Category.user_id == current_user.id)
    ).first()
    if not category:
        raise HTTPException(status_code=404, detail="Kategorie nicht gefunden")
    return category


@app.patch("/categories/{key}", response_model=CategoryOut)
def update_category(
    key: str,
    data: CategoryCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    category = _get_owned_category(key, session, current_user)
    label = data.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="Name darf nicht leer sein")
    category.label = label
    category.icon = data.icon
    category.color = data.color
    session.add(category)
    session.commit()
    session.refresh(category)
    return CategoryOut(key=category.key, label=category.label, icon=category.icon, color=category.color, custom=True)


@app.delete("/categories/{key}")
def delete_category(
    key: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    category = _get_owned_category(key, session, current_user)
    # Habits, die diese Kategorie nutzen, fallen auf "Sonstiges" zurück,
    # damit sie nicht mit einer nicht mehr existierenden Kategorie verwaist.
    habits = session.exec(
        select(Habit).where(Habit.user_id == current_user.id, Habit.category == key)
    ).all()
    for habit in habits:
        habit.category = "other"
        session.add(habit)
    session.delete(category)
    session.commit()
    return {"ok": True, "habits_reassigned": len(habits)}


# ---------------------------------------------------------------------------
# Habit-Endpunkte (jetzt alle geschützt durch Login)
# ---------------------------------------------------------------------------

@app.get("/habits", response_model=List[HabitRead])
def list_habits(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    return [_to_read_model(h) for h in habits]


@app.post("/habits", response_model=HabitRead)
def create_habit(
    data: HabitCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habit = Habit(
        title=data.title,
        category=data.category,
        icon=data.icon,
        color=data.color,
        notes=data.notes,
        reminder_time=data.reminder_time,
        active_weekdays=_weekdays_to_str(data.active_weekdays),
        user_id=current_user.id,
    )
    current_user.total_habits_created += 1
    session.add(current_user)
    session.add(habit)
    session.commit()
    session.refresh(habit)
    return _to_read_model(habit)


def _get_owned_habit(habit_id: int, session: Session, current_user: User) -> Habit:
    habit = session.get(Habit, habit_id)
    if not habit or habit.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Habit nicht gefunden")
    return habit


class HabitUpdate(SQLModel):
    title: Optional[str] = None
    category: Optional[str] = None
    icon: Optional[str] = None
    clear_icon: bool = False  # explizit auf Kategorie-Icon zurücksetzen
    color: Optional[str] = None
    clear_color: bool = False  # explizit auf Kategorie-Farbe zurücksetzen
    notes: Optional[str] = None
    clear_notes: bool = False  # explizit Notiz löschen
    reminder_time: Optional[str] = None
    clear_reminder: bool = False  # explizit auf "keine Erinnerung" setzen
    active_weekdays: Optional[List[int]] = None
    clear_weekdays: bool = False  # explizit auf "jeden Tag" zurücksetzen


@app.patch("/habits/{habit_id}", response_model=HabitRead)
def update_habit(
    habit_id: int,
    data: HabitUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habit = _get_owned_habit(habit_id, session, current_user)

    if data.title is not None:
        habit.title = data.title
    if data.category is not None:
        habit.category = data.category
    if data.clear_icon:
        habit.icon = None
    elif data.icon is not None:
        habit.icon = data.icon
    if data.clear_color:
        habit.color = None
    elif data.color is not None:
        habit.color = data.color
    if data.clear_notes:
        habit.notes = None
    elif data.notes is not None:
        habit.notes = data.notes
    if data.clear_reminder:
        habit.reminder_time = None
    elif data.reminder_time is not None:
        habit.reminder_time = data.reminder_time
    if data.clear_weekdays:
        habit.active_weekdays = None
    elif data.active_weekdays is not None:
        habit.active_weekdays = _weekdays_to_str(data.active_weekdays)

    session.add(habit)
    session.commit()
    session.refresh(habit)
    return _to_read_model(habit)


@app.delete("/habits/{habit_id}")
def delete_habit(
    habit_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habit = _get_owned_habit(habit_id, session, current_user)
    # Erst alle "erledigt am X"-Einträge zu diesem Habit löschen - sonst
    # verweigert die Datenbank das Löschen des Habits selbst (Fremdschlüssel).
    logs = session.exec(select(HabitLog).where(HabitLog.habit_id == habit_id)).all()
    for log in logs:
        session.delete(log)
    # WICHTIG: flush() zwingt die Log-Löschungen JETZT auszuführen, bevor wir
    # das Habit selbst löschen. Ohne das kann die Datenbank beide Löschungen
    # in der falschen Reihenfolge verarbeiten (Habit vor den Logs) und dann
    # mit einem Fremdschlüssel-Fehler abbrechen.
    session.flush()
    session.delete(habit)
    session.commit()
    return {"ok": True}


class CompleteHabitResponse(SQLModel):
    habit: HabitRead
    points_earned: int
    freeze_used: bool
    total_points: int
    level: int
    leveled_up: bool
    streak_bonus_earned: int = 0  # +100 XP einmalig bei genau 7 Tagen Streak
    all_done_bonus_earned: int = 0  # +50 XP einmalig, wenn heute ALLE Habits erledigt sind


@app.post("/habits/{habit_id}/complete", response_model=CompleteHabitResponse)
def complete_habit(
    habit_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habit = _get_owned_habit(habit_id, session, current_user)

    today = date.today()
    if habit.last_completed == today:
        # Heute schon erledigt -> keine erneuten Punkte, nichts ändert sich
        level_info = _compute_level(current_user.points)
        return CompleteHabitResponse(
            habit=_to_read_model(habit),
            points_earned=0,
            freeze_used=False,
            total_points=current_user.points,
            level=level_info["level"],
            leveled_up=False,
        )

    _maybe_refill_streak_freeze(current_user)

    weekdays = _parse_weekdays(habit.active_weekdays)
    prev_scheduled = _previous_scheduled_day(weekdays, today)
    prev_prev_scheduled = _previous_scheduled_day(weekdays, prev_scheduled)
    freeze_used = False

    if habit.last_completed == prev_scheduled:
        habit.current_streak += 1
    elif habit.last_completed == prev_prev_scheduled and current_user.streak_freezes_available > 0:
        # Genau ein geplanter Tag verpasst, aber ein Freeze ist da -> Streak gerettet!
        current_user.streak_freezes_available -= 1
        current_user.freezes_used_count += 1
        habit.current_streak += 1
        freeze_used = True
    else:
        habit.current_streak = 1

    habit.best_streak = max(habit.best_streak, habit.current_streak)
    habit.last_completed = today

    # Punkte: Grundpunkte + kleiner Bonus für längere Streaks
    points_earned = 10 + min(habit.current_streak, 20)  # Bonus gedeckelt bei 20

    # Bonus 1: Genau 7 Tage Streak erreicht -> einmaliger Bonus für DIESES Habit
    streak_bonus_earned = 0
    if habit.current_streak == 7:
        streak_bonus_earned = 100
        points_earned += streak_bonus_earned

    points_before = current_user.points
    level_before = _compute_level(points_before)["level"]

    current_user.points += points_earned
    current_user.total_completions += 1

    # Bonus 2: Sind nach dieser Erledigung ALLE Habits des Nutzers heute erledigt?
    # (nur einmal pro Tag auszahlen, dafür last_all_done_bonus_date als Sperre)
    all_done_bonus_earned = 0
    all_habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    all_done_today = all(h.last_completed == today for h in all_habits)
    if all_done_today and current_user.last_all_done_bonus_date != today:
        all_done_bonus_earned = 50
        current_user.points += all_done_bonus_earned
        current_user.last_all_done_bonus_date = today

    level_after_info = _compute_level(current_user.points)
    leveled_up = level_after_info["level"] > level_before

    now = datetime.utcnow()
    session.add(HabitLog(habit_id=habit.id, completed_on=today, completed_at=now))
    session.add(PointsLog(user_id=current_user.id, points=points_earned + all_done_bonus_earned, earned_on=today))
    session.add(habit)
    session.add(current_user)
    session.commit()
    session.refresh(habit)
    session.refresh(current_user)

    return CompleteHabitResponse(
        habit=_to_read_model(habit),
        points_earned=points_earned + all_done_bonus_earned,
        freeze_used=freeze_used,
        total_points=current_user.points,
        level=level_after_info["level"],
        leveled_up=leveled_up,
        streak_bonus_earned=streak_bonus_earned,
        all_done_bonus_earned=all_done_bonus_earned,
    )


@app.get("/habits/{habit_id}/stats")
def habit_stats(
    habit_id: int,
    period: str = "week",  # "week" | "month" | "all"
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Statistik für EIN Habit über einen wählbaren Zeitraum - für die
    Habit-Detailseite (Erledigungsrate, Durchschnitt pro Woche)."""
    habit = _get_owned_habit(habit_id, session, current_user)
    today = date.today()

    if period == "week":
        start = today - timedelta(days=today.weekday())  # Montag dieser Woche
        possible_days = (today - start).days + 1
    elif period == "month":
        start = date(today.year, today.month, 1)
        possible_days = (today - start).days + 1
    else:  # "all"
        start = habit.created_at.date()
        possible_days = max((today - start).days + 1, 1)

    logs = session.exec(
        select(HabitLog).where(HabitLog.habit_id == habit_id, HabitLog.completed_on >= start)
    ).all()
    completions_in_period = len(logs)

    # Bei Wochentage-Habits sind nicht alle Tage "möglich" - nur die geplanten.
    weekdays = _parse_weekdays(habit.active_weekdays)
    if weekdays:
        possible_days = sum(
            1 for i in range(possible_days) if (start + timedelta(days=i)).isoweekday() in weekdays
        )
    possible_days = max(possible_days, 1)

    completion_rate = round((completions_in_period / possible_days) * 100)
    weeks_in_period = max(possible_days / 7, 1 / 7)
    avg_per_week = round(completions_in_period / weeks_in_period, 1)

    return {
        "period": period,
        "completion_rate": min(completion_rate, 100),
        "avg_per_week": avg_per_week,
        "total_completions_in_period": completions_in_period,
    }


@app.get("/habits/{habit_id}/history")
def habit_history(
    habit_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Gibt alle Tage zurück, an denen dieses Habit erledigt wurde."""
    _get_owned_habit(habit_id, session, current_user)  # prüft Zugriffsrecht
    logs = session.exec(
        select(HabitLog).where(HabitLog.habit_id == habit_id)
    ).all()
    return {"dates": sorted([log.completed_on.isoformat() for log in logs])}


@app.get("/stats/overview")
def stats_overview(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Übersichts-Statistik über alle Habits eines Nutzers."""
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    habit_ids = [h.id for h in habits]

    if not habit_ids:
        return {
            "total_habits": 0,
            "completions_last_7_days": 0,
            "completions_last_30_days": 0,
            "best_streak_overall": 0,
            "best_streak_habit_title": None,
            "habits_created_last_7_days": 0,
            "daily_completions": [],
        }

    all_logs = session.exec(
        select(HabitLog).where(HabitLog.habit_id.in_(habit_ids))
    ).all()

    today = date.today()
    last_7 = today - timedelta(days=7)
    last_30 = today - timedelta(days=30)

    completions_7 = sum(1 for log in all_logs if log.completed_on >= last_7)
    completions_30 = sum(1 for log in all_logs if log.completed_on >= last_30)

    best_habit = max(habits, key=lambda h: h.best_streak, default=None)
    best_streak_overall = best_habit.best_streak if best_habit else 0
    best_streak_habit_title = best_habit.title if best_habit and best_habit.best_streak > 0 else None

    habits_created_last_7_days = sum(
        1 for h in habits if h.created_at.date() >= last_7
    )

    # Für die letzten 14 Tage: wie viele Habits wurden an jedem Tag erledigt
    daily_completions = []
    for i in range(13, -1, -1):
        day = today - timedelta(days=i)
        count = sum(1 for log in all_logs if log.completed_on == day)
        daily_completions.append({"date": day.isoformat(), "count": count})

    return {
        "total_habits": len(habits),
        "completions_last_7_days": completions_7,
        "completions_last_30_days": completions_30,
        "best_streak_overall": best_streak_overall,
        "best_streak_habit_title": best_streak_habit_title,
        "habits_created_last_7_days": habits_created_last_7_days,
        "daily_completions": daily_completions,
    }


@app.get("/stats/completion_history")
def completion_history(
    period: str = "week",  # "week" | "last_week" | "month"
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Tägliche Erledigungsrate (in %) für einen wählbaren Zeitraum -
    für das Liniendiagramm auf der Statistik-Hauptseite."""
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    habit_ids = [h.id for h in habits]
    total_habits = len(habits)

    today = date.today()
    if period == "last_week":
        start = today - timedelta(days=today.weekday() + 7)
        end = start + timedelta(days=6)
    elif period == "month":
        start = date(today.year, today.month, 1)
        end = today
    else:  # "week"
        start = today - timedelta(days=today.weekday())
        end = today

    if not habit_ids or total_habits == 0:
        return {"period": period, "points": [], "overall_completion_rate": 0}

    logs = session.exec(
        select(HabitLog).where(
            HabitLog.habit_id.in_(habit_ids),
            HabitLog.completed_on >= start,
            HabitLog.completed_on <= end,
        )
    ).all()

    points = []
    day = start
    total_possible = 0
    total_done = 0
    while day <= end and day <= today:
        done_count = sum(1 for log in logs if log.completed_on == day)
        rate = round((done_count / total_habits) * 100)
        points.append({"date": day.isoformat(), "rate": min(rate, 100)})
        total_possible += total_habits
        total_done += done_count
        day += timedelta(days=1)

    overall_rate = round((total_done / total_possible) * 100) if total_possible > 0 else 0

    return {"period": period, "points": points, "overall_completion_rate": min(overall_rate, 100)}


@app.get("/profile")
def get_profile(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    _maybe_refill_streak_freeze(current_user)
    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    level_info = _compute_level(current_user.points)
    return {
        "username": current_user.username,
        "points": current_user.points,
        "level": level_info["level"],
        "points_into_level": level_info["points_into_level"],
        "points_needed_for_next_level": level_info["points_needed_for_next_level"],
        "total_completions": current_user.total_completions,
        "streak_freezes_available": current_user.streak_freezes_available,
    }


# Feste Liste aller möglichen Abzeichen. "check" ist eine Funktion, die anhand
# der Nutzer-Statistik entscheidet, ob das Abzeichen freigeschaltet ist.
def _badge_definitions():
    return [
        {
            "id": "first_habit",
            "label": "Erster Schritt",
            "description": "Erstelle dein erstes Habit",
            "icon": "flag",
            "check": lambda stats: stats["total_habits"] >= 1,
            "progress": lambda stats: min(stats["total_habits"], 1),
            "target": 1,
        },
        {
            "id": "five_habits",
            "label": "Sammler",
            "description": "Lege 5 aktive Habits an",
            "icon": "collections",
            "check": lambda stats: stats["total_habits"] >= 5,
            "progress": lambda stats: min(stats["total_habits"], 5),
            "target": 5,
        },
        {
            "id": "ten_completions",
            "label": "In Fahrt",
            "description": "Erledige insgesamt 10 Habits",
            "icon": "trending_up",
            "check": lambda stats: stats["total_completions"] >= 10,
            "progress": lambda stats: min(stats["total_completions"], 10),
            "target": 10,
        },
        {
            "id": "century",
            "label": "Jahrhundert-Klub",
            "description": "Erledige insgesamt 100 Habits",
            "icon": "military_tech",
            "check": lambda stats: stats["total_completions"] >= 100,
            "progress": lambda stats: min(stats["total_completions"], 100),
            "target": 100,
        },
        {
            "id": "week_streak",
            "label": "Eine Woche stark",
            "description": "Erreiche eine 7-Tage-Streak",
            "icon": "local_fire_department",
            "check": lambda stats: stats["best_streak_overall"] >= 7,
            "progress": lambda stats: min(stats["best_streak_overall"], 7),
            "target": 7,
        },
        {
            "id": "month_streak",
            "label": "Monats-Meister",
            "description": "Erreiche eine 30-Tage-Streak",
            "icon": "emoji_events",
            "check": lambda stats: stats["best_streak_overall"] >= 30,
            "progress": lambda stats: min(stats["best_streak_overall"], 30),
            "target": 30,
        },
        {
            "id": "freeze_saver",
            "label": "Cool geblieben",
            "description": "Rette eine Streak mit einem Freeze",
            "icon": "ac_unit",
            "check": lambda stats: stats["freezes_used_count"] >= 1,
            "progress": lambda stats: min(stats["freezes_used_count"], 1),
            "target": 1,
        },
        {
            "id": "level_five",
            "label": "Aufsteiger",
            "description": "Erreiche Level 5",
            "icon": "rocket_launch",
            "check": lambda stats: stats["level"] >= 5,
            "progress": lambda stats: min(stats["level"], 5),
            "target": 5,
        },
        {
            "id": "early_bird",
            "label": "Früher Vogel",
            "description": "Schließe ein Habit vor 08:00 Uhr ab",
            "icon": "wb_sunny",
            "check": lambda stats: stats["early_bird_count"] >= 1,
            "progress": lambda stats: min(stats["early_bird_count"], 1),
            "target": 1,
        },
        {
            "id": "night_owl",
            "label": "Nachtmensch",
            "description": "Schließe ein Habit nach 22:00 Uhr ab",
            "icon": "bedtime",
            "check": lambda stats: stats["night_owl_count"] >= 1,
            "progress": lambda stats: min(stats["night_owl_count"], 1),
            "target": 1,
        },
        {
            "id": "goal_oriented",
            "label": "Zielstrebig",
            "description": "Erstelle insgesamt 10 Habits",
            "icon": "flag_circle",
            "check": lambda stats: stats["total_habits_created"] >= 10,
            "progress": lambda stats: min(stats["total_habits_created"], 10),
            "target": 10,
        },
        {
            "id": "perfect_week",
            "label": "Perfekte Woche",
            "description": "Erledige an 7 Tagen in Folge alle Habits",
            "icon": "verified",
            "check": lambda stats: stats["perfect_days_streak"] >= 7,
            "progress": lambda stats: min(stats["perfect_days_streak"], 7),
            "target": 7,
        },
    ]


def _count_logs_before_hour(logs: list, hour: int) -> int:
    """Zählt Erledigungen mit Zeitstempel VOR der angegebenen Stunde (lokale Zeit)."""
    return sum(1 for log in logs if log.completed_at and log.completed_at.hour < hour)


def _count_logs_after_hour(logs: list, hour: int) -> int:
    """Zählt Erledigungen mit Zeitstempel AB der angegebenen Stunde (lokale Zeit)."""
    return sum(1 for log in logs if log.completed_at and log.completed_at.hour >= hour)


def _compute_perfect_days_streak(habits: list, session: Session) -> int:
    """Wie viele der letzten Tage (rückwärts ab heute) wurden ALLE Habits
    erledigt? Zählung stoppt beim ersten unvollständigen Tag."""
    if not habits:
        return 0

    habit_ids = [h.id for h in habits]
    logs = session.exec(select(HabitLog).where(HabitLog.habit_id.in_(habit_ids))).all()

    streak = 0
    day = date.today()
    for _ in range(30):  # mehr als genug, Badge braucht nur 7
        completed_habit_ids = {log.habit_id for log in logs if log.completed_on == day}
        if set(habit_ids).issubset(completed_habit_ids):
            streak += 1
            day -= timedelta(days=1)
        else:
            break
    return streak


@app.get("/badges")
def get_badges(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    best_streak_overall = max((h.best_streak for h in habits), default=0)
    level_info = _compute_level(current_user.points)

    habit_ids = [h.id for h in habits]
    all_logs = (
        session.exec(select(HabitLog).where(HabitLog.habit_id.in_(habit_ids))).all()
        if habit_ids
        else []
    )

    stats = {
        "total_habits": len(habits),
        "total_completions": current_user.total_completions,
        "best_streak_overall": best_streak_overall,
        "freezes_used_count": current_user.freezes_used_count,
        "level": level_info["level"],
        "early_bird_count": _count_logs_before_hour(all_logs, 8),
        "night_owl_count": _count_logs_after_hour(all_logs, 22),
        "total_habits_created": current_user.total_habits_created,
        "perfect_days_streak": _compute_perfect_days_streak(habits, session),
    }

    result = []
    for badge in _badge_definitions():
        result.append({
            "id": badge["id"],
            "label": badge["label"],
            "description": badge["description"],
            "icon": badge["icon"],
            "earned": badge["check"](stats),
            "progress": badge["progress"](stats),
            "target": badge["target"],
        })
    return {"badges": result}


@app.get("/stats/xp_history")
def xp_history(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """XP-Gewinn pro Tag der letzten 7 Tage - für den Level-Verlauf-Chart."""
    today = date.today()
    week_start = today - timedelta(days=6)

    logs = session.exec(
        select(PointsLog).where(
            PointsLog.user_id == current_user.id,
            PointsLog.earned_on >= week_start,
        )
    ).all()

    daily_points = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        total = sum(log.points for log in logs if log.earned_on == day)
        daily_points.append({"date": day.isoformat(), "points": total})

    return {"daily_points": daily_points}


@app.get("/export/csv")
def export_csv(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Exportiert alle Habits + deren Erledigungs-Historie als CSV-Text.
    Wird vom Frontend zum Kopieren/Speichern angeboten (kein Datei-Download
    nötig, da das plattformübergreifend in Flutter kompliziert wäre)."""
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()

    lines = ["Habit,Kategorie,Erledigt am"]
    for habit in habits:
        logs = session.exec(
            select(HabitLog).where(HabitLog.habit_id == habit.id).order_by(HabitLog.completed_on)
        ).all()
        if not logs:
            lines.append(f'"{habit.title}",{habit.category},')
        for log in logs:
            lines.append(f'"{habit.title}",{habit.category},{log.completed_on.isoformat()}')

    return {"csv": "\n".join(lines)}


@app.delete("/account")
def delete_account(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Löscht den Nutzer-Account unwiderruflich, inklusive aller Habits,
    deren Historie und der Punkte-Historie."""
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    for habit in habits:
        logs = session.exec(select(HabitLog).where(HabitLog.habit_id == habit.id)).all()
        for log in logs:
            session.delete(log)
        session.delete(habit)

    points_logs = session.exec(select(PointsLog).where(PointsLog.user_id == current_user.id)).all()
    for log in points_logs:
        session.delete(log)

    session.delete(current_user)
    session.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Backup & Wiederherstellung
# ---------------------------------------------------------------------------
# Da die Daten sowieso live in der Cloud-Datenbank liegen, ist das hier vor
# allem eine zusätzliche Sicherheit (z.B. vor "Konto löschen", oder um Daten
# manuell auf ein neues Konto zu übertragen). Kein Datei-Download nötig -
# genau wie beim CSV-Export wird JSON-Text zum Kopieren angeboten.

class BackupHabit(SQLModel):
    title: str
    category: str
    icon: Optional[str] = None
    color: Optional[str] = None
    notes: Optional[str] = None
    reminder_time: Optional[str] = None
    active_weekdays: Optional[List[int]] = None
    current_streak: int = 0
    best_streak: int = 0
    last_completed: Optional[date] = None
    completed_on: List[str] = []  # ISO-Daten aller Erledigungen


class BackupCategory(SQLModel):
    key: str
    label: str
    icon: str
    color: str


class BackupData(SQLModel):
    version: int = 1
    points: int = 0
    streak_freezes_available: int = 1
    freezes_used_count: int = 0
    total_habits_created: int = 0
    categories: List[BackupCategory] = []
    habits: List[BackupHabit] = []


@app.get("/backup/export", response_model=BackupData)
def export_backup(
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    own_categories = session.exec(select(Category).where(Category.user_id == current_user.id)).all()

    backup_habits = []
    for habit in habits:
        logs = session.exec(select(HabitLog).where(HabitLog.habit_id == habit.id)).all()
        backup_habits.append(BackupHabit(
            title=habit.title,
            category=habit.category,
            icon=habit.icon,
            color=habit.color,
            notes=habit.notes,
            reminder_time=habit.reminder_time,
            active_weekdays=_parse_weekdays(habit.active_weekdays),
            current_streak=habit.current_streak,
            best_streak=habit.best_streak,
            last_completed=habit.last_completed,
            completed_on=[log.completed_on.isoformat() for log in logs],
        ))

    return BackupData(
        points=current_user.points,
        streak_freezes_available=current_user.streak_freezes_available,
        freezes_used_count=current_user.freezes_used_count,
        total_habits_created=current_user.total_habits_created,
        categories=[
            BackupCategory(key=c.key, label=c.label, icon=c.icon, color=c.color) for c in own_categories
        ],
        habits=backup_habits,
    )


@app.post("/backup/import")
def import_backup(
    data: BackupData,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """Ersetzt ALLE aktuellen Habits, eigenen Kategorien und Punkte des
    Nutzers durch den Inhalt des Backups. Das ist bewusst ein vollständiges
    Wiederherstellen (kein Zusammenführen), damit das Ergebnis vorhersehbar
    bleibt - die App warnt den Nutzer davor, bevor sie diesen Endpunkt ruft."""
    # Bestehende Habits (inkl. Verlauf) löschen
    existing_habits = session.exec(select(Habit).where(Habit.user_id == current_user.id)).all()
    for habit in existing_habits:
        logs = session.exec(select(HabitLog).where(HabitLog.habit_id == habit.id)).all()
        for log in logs:
            session.delete(log)
        session.delete(habit)

    # Bestehende eigene Kategorien löschen
    existing_categories = session.exec(select(Category).where(Category.user_id == current_user.id)).all()
    for category in existing_categories:
        session.delete(category)
    session.commit()

    # Eigene Kategorien wiederherstellen
    for cat in data.categories:
        session.add(Category(user_id=current_user.id, key=cat.key, label=cat.label, icon=cat.icon, color=cat.color))

    # Habits + Verlauf wiederherstellen
    for h in data.habits:
        habit = Habit(
            user_id=current_user.id,
            title=h.title,
            category=h.category,
            icon=h.icon,
            color=h.color,
            notes=h.notes,
            reminder_time=h.reminder_time,
            active_weekdays=_weekdays_to_str(h.active_weekdays),
            current_streak=h.current_streak,
            best_streak=h.best_streak,
            last_completed=h.last_completed,
        )
        session.add(habit)
        session.commit()
        session.refresh(habit)
        for completed_on in h.completed_on:
            session.add(HabitLog(habit_id=habit.id, completed_on=date.fromisoformat(completed_on)))

    # Nutzer-Statistiken wiederherstellen
    current_user.points = data.points
    current_user.streak_freezes_available = data.streak_freezes_available
    current_user.freezes_used_count = data.freezes_used_count
    current_user.total_habits_created = data.total_habits_created
    session.add(current_user)
    session.commit()

    return {"ok": True, "habits_restored": len(data.habits)}


@app.get("/")
def root():
    return {"status": "ok", "message": "Habit Tracker API läuft"}
