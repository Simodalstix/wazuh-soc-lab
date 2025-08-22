pipeline {
    agent any
    
    stages {
        stage('Deploy VMs') {
            steps {
                sh 'vagrant up'
            }
        }
        
        stage('Configure Systems') {
            steps {
                sh 'cd ansible.minimal && ansible-playbook -i inventory.yml site.yml'
            }
        }
        
        stage('Test') {
            steps {
                sh 'curl -f http://192.168.56.20/dvwa || exit 1'
                sh 'curl -f -k https://192.168.56.10 || exit 1'
            }
        }
    }
    
    post {
        always {
            sh 'vagrant destroy -f'
        }
    }
}