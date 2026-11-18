pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo '=== Construyendo imagen Docker y entorno Python ==='
                sh '''
                    python3 -m venv .venv
                    .venv/bin/pip install --upgrade pip
                    .venv/bin/pip install -r requirements.txt bandit pip-audit
                    docker build -t appsegura .
                '''
            }
        }

        stage('Test') {
            steps {
                echo '=== Ejecutando pruebas unitarias (pytest) ==='
                sh '.venv/bin/pytest -v'
            }
        }

        stage('SAST & Dependency Audit') {
            steps {
                echo '=== Revision SAST con Bandit ==='
                sh '''
                    .venv/bin/bandit -r app.py -f txt -o bandit-report.txt || true
                    cat bandit-report.txt
                '''
                echo '=== Auditoria de dependencias con pip-audit ==='
                sh '''
                    .venv/bin/pip-audit -r requirements.txt || true
                '''
            }
        }

        stage('Deploy') {
            steps {
                echo '=== Desplegando aplicacion en red securedev-net ==='
                sh '''
                    docker rm -f securedev-app || true
                    docker run -d --name securedev-app --network securedev-net -p 5000:5000 appsegura
                    sleep 3
                    curl -f http://securedev-app:5000/health
                '''
            }
        }

        stage('Security Test (OWASP ZAP)') {
            steps {
                echo '=== Ejecutando escaneo dinamico (DAST) con OWASP ZAP ==='
                sh '''
                    docker rm -f securedev-zap || true
                    docker run --name securedev-zap --network securedev-net ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://securedev-app:5000 -r zap_report.html || true
                    docker cp securedev-zap:/zap/wrk/zap_report.html ./zap_report.html || true
                    docker rm -f securedev-zap || true
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'bandit-report.txt, zap_report.html', allowEmptyArchive: true
        }
    }
}
