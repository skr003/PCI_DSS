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
          sh 'terraform show -json tfplan > tfscan.json'
          archiveArtifacts artifacts: 'tfscan.json', followSymlinks: false
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
        sh 'pwd'
        sh 'ls'
        sh 'opa eval --input output/azure.json --data policy/azure/pci_dss.rego "data.pci_dss.deny"'
        sh 'opa eval --input output/azure.json --data policy/azure/pci_dss.rego "data.azure.pci_dss.allow"'
      }  
    }
    stage('Upload Reports to Azure Storage') {
      steps {
        withCredentials([
          string(credentialsId: 'AZURE_CLIENT_ID', variable: 'AZURE_CLIENT_ID'),
          string(credentialsId: 'AZURE_CLIENT_SECRET', variable: 'AZURE_CLIENT_SECRET'),
          string(credentialsId: 'AZURE_TENANT_ID', variable: 'AZURE_TENANT_ID'),
          string(credentialsId: 'STORAGE_ACCOUNT_KEY', variable: 'STORAGE_ACCOUNT_KEY', defaultValue: 'pUsU+U4ZVzYx5jVJAyiEXeVIhgel/4iGxqYl+cY1WSJI5NKsvlbYN5Si9NXHr8TKQTB92BHvTH64+AStjLZLuQ==')
        ]) {
          sh '''
            # Set variables
            STORAGE_ACCOUNT="reportingpcidss25655"
            CONTAINER="reports"
            
            # Diagnostic: Test DNS resolution
            nslookup $STORAGE_ACCOUNT.blob.core.windows.net || echo "DNS resolution failed"
            
            # Check if files exist
            if [ ! -f output/pci_dss_drifts.json ]; then echo "Error: pci_dss_drifts.json not found"; exit 1; fi
            if [ ! -f output/azure.json ]; then echo "Error: azure.json not found"; exit 1; fi
            
            # Upload to build-specific path
            az storage blob upload --container-name $CONTAINER --name "builds/$BUILD_NUMBER/pci_dss_drifts.json" --file output/pci_dss_drifts.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY"
            az storage blob upload --container-name $CONTAINER --name "builds/$BUILD_NUMBER/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY"
            
            # Upload to 'latest' path
            az storage blob upload --container-name $CONTAINER --name "latest/pci_dss_drifts.json" --file output/pci_dss_drifts.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY"
            az storage blob upload --container-name $CONTAINER --name "latest/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --account-key "$STORAGE_ACCOUNT_KEY"
          '''
        }
      }
    }
  }
}
