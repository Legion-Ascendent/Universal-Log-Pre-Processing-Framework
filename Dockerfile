# Python base image (small, but has prebuilt wheels for pandas etc. on Debian)
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (separate layer) so rebuilds after code-only
# changes don't have to re-download/reinstall every package.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Now copy the rest of the repo in.
COPY . .

EXPOSE 8501

# --server.headless=true avoids Streamlit's first-run interactive email
# prompt, which would otherwise hang forever with no terminal attached.
# --browser.gatherUsageStats=false avoids Streamlit trying to phone home,
# keeping this fully quiet with zero internet access at runtime.
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true", \
     "--browser.gatherUsageStats=false"]