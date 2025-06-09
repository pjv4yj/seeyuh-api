# SEEYUH API

## MacOS Vulnerability Research API built on top of OpenAI Agent SDK API

### Installing and Running
```
git clone https://github.com/pjv4yj/seeyuh-api.git
cd seeyuh-api
```

Follow the steps here to setup your environment for the OpenAI Agent SDK: https://openai.github.io/openai-agents-python/quickstart/

Install other required dependencies in your virtual environment

```
pip install -r requirements.txt
```

Be sure to set your OpenAI API key as an environment variable:
```
export OPENAI_API_KEY=sk...
```

Run the FastAPI Server:

```
uvicorn fastapi_server:app --reload
```

### Use

API should now be live at ```http://127.0.0.1:8000```

*NOTE:* Install the UI for easiest use! (https://github.com/pjv4yj/seeyuh-ui)
