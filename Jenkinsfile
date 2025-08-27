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
          string(credentialsId: 'AZURE_TENANT_ID', variable: 'AZURE_TENANT_ID')
        ]) {
          sh '''
            # Set variables
            STORAGE_ACCOUNT="reporting-pcidss"
            CONTAINER="reports"
            
            # Re-authenticate for this stage
            az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"
            
            # Diagnostic: Test DNS resolution
            nslookup reporting-pcidss.blob.core.windows.net || echo "DNS resolution failed"
            
            # Diagnostic: Test internet access
            curl -I https://www.google.com || echo "Internet access failed"
            
            # Ensure container exists with public access
            az storage container create --name $CONTAINER --account-name $STORAGE_ACCOUNT --public-access blob --auth-mode login || true
            
            # Define build-specific and latest paths
            BUILD_DIR="builds/$BUILD_NUMBER"
            LATEST_DIR="latest"
            
            # Check if files exist
            if [ ! -f output/pci_dss_drifts.json ]; then echo "Error: pci_dss_drifts.json not found"; exit 1; fi
            if [ ! -f output/azure.json ]; then echo "Error: azure.json not found"; exit 1; fi
            
            # Upload to build-specific path
            az storage blob upload --container-name $CONTAINER --name "$BUILD_DIR/pci_dss_drifts.json" --file output/pci_dss_drifts.json --account-name $STORAGE_ACCOUNT --auth-mode login
            az storage blob upload --container-name $CONTAINER --name "$BUILD_DIR/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --auth-mode login
            
            # Upload to 'latest' path
            az storage blob upload --container-name $CONTAINER --name "$LATEST_DIR/pci_dss_drifts.json" --file output/pci_dss_drifts.json --account-name $STORAGE_ACCOUNT --auth-mode login
            az storage blob upload --container-name $CONTAINER --name "$LATEST_DIR/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --auth-mode login
          '''
        }
      }
    }
  }
}
