pipeline {
  agent any
  stages {
    stage('Checkout IaC Code') {
      steps {
        checkout scm
      }
    }
    stage('IaC Static Analysis') {
      steps {
              sh 'checkov -d terraform || true'
      }
    }
    stage('Terraform Init & Plan') {
      steps {
         dir('terraform') {
                withCredentials([
                    string(credentialsId: 'AZURE_CLIENT_ID', variable: 'AZURE_CLIENT_ID'),
                    string(credentialsId: 'AZURE_CLIENT_SECRET', variable: 'AZURE_CLIENT_SECRET'),
                    string(credentialsId: 'AZURE_TENANT_ID', variable: 'AZURE_TENANT_ID'),
                    string(credentialsId: 'AZURE_SUBSCRIPTION_ID', variable: 'AZURE_SUBSCRIPTION_ID')
                ]) {
                    sh 'az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"'
                    sh 'az account set --subscription "$AZURE_SUBSCRIPTION_ID"'
                }           
             sh 'terraform init -upgrade'
             sh 'terraform plan -out=tfplan'
             sh 'terraform show -json tfplan > azure.json'
             archiveArtifacts artifacts: 'azure.json', followSymlinks: false
      }  
      }   
    }

        stage('Collect Azure Data') {
            steps {
                sh 'bash scripts/collect_azure_data.sh'
            }
        }
        stage('Validate PCI DSS') {
            steps {
                sh 'bash scripts/validate_pci.sh'
            }
        }




    
    stage('OPA Policy Validation') {
      steps {
        dir('IaC-Project/terraform') {
     //   sh 'opa eval --format pretty --data ../opa/policy.rego --input tfplan.json "data.policies.allow"'  
          sh 'opa eval --input azure.json --data poliy/azure/pci_dss.rego "data.pci_dss.deny"'

      }
      }  
    }
    stage('Approve or Reject Deployment') {
      steps {
        dir('IaC-Project/opa') {
        script {
          def opaOutput = sh(script: 'opa eval --format pretty --data policy.rego --input ../terraform/tfplan.json "data.policies.allow"', returnStdout: true).trim()
          if (opaOutput != "true") {
            error("OPA policy denied the deployment! Aborting pipeline.")
          } else {
            echo "OPA policy approved the deployment."
          }
        }
      }
      }  
    }
  }
}
