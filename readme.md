# PrivateCloud Backend

### Step-1: Intialize the Environment

```bash
virtualenv env
```

### Step-2: Activate the Environment

```bash
.\env\Scripts\activate
```

### Step-3: Install all dependencies

```bash
pip install .
```
or
```bash
pip install -r requirements.txt
```

### Step-4: [DEV] Starting development server

```bash
flask run --debug
```

### Step-4: [DEPLOY] Starting deployment server

```bash
flask run
```
