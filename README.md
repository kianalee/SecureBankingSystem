# SecureBankingSystem

SecureBankingSystem now includes:

- `BankServer.py`: the original socket-based banking server, now configured through environment variables.
- `ATMClient.py`: a CLI ATM that uses the shared protocol client.
- `secure_banking/gateway.py`: a FastAPI gateway that lets a browser drive ATM sessions without exposing socket keys.
- `frontend/`: a React + Vite + TypeScript GUI with `/app` and `/admin` routes.

## Environment

Copy `.env.example` values into your shell or environment manager:

- `BANK_SERVER_HOST`
- `BANK_SERVER_PORT`
- `FIREBASE_WEB_API_KEY`
- `FIREBASE_SERVICE_ACCOUNT_PATH`
- `GATEWAY_SESSION_SECRET`
- `FRONTEND_ORIGINS`
- `ADMIN_PANEL_PASSWORD`
- `AUDIT_LOG_PATH`

## Backend setup

Install Python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the bank server:

```bash
python3 BankServer.py
```

Run the FastAPI gateway:

```bash
python3 -m uvicorn secure_banking.gateway:app --reload --port 8000
```

## One-command launch

If `.env` is present, the Python apps now load it automatically.

Run the bank server plus gateway together:

```bash
python3 run_stack.py
```

If you want the live Vite dev server instead of the built frontend served by FastAPI:

```bash
python3 run_stack.py --frontend-dev
```

## Frontend setup

Install frontend dependencies:

```bash
cd frontend
npm install
```

Start the browser app:

```bash
npm run dev
```

The Vite dev server runs on `http://localhost:5173` and proxies API requests to `http://localhost:8000`.

After `npm run build`, the gateway can also serve `frontend/dist` directly at `http://127.0.0.1:8000/`.

## Demo checklist

1. Start the stack with `python3 run_stack.py`.
2. Open `/app`, connect `ATM Aurora`, log in, then perform 2-3 actions such as deposit, withdraw, and balance.
3. Open a second tab or window, choose another client ID, and repeat the flow for a different customer.
4. Open `/admin` and confirm the latest entries plus the local audit log file path.

## Tests

Backend:

```bash
pytest
```

Frontend:

```bash
cd frontend
npm test
```
