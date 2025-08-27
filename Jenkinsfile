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
        sh '''
          # Set variables
          STORAGE_ACCOUNT="reporting-pcidss"  # Corrected to your storage account name
          CONTAINER="reports"
          
          # Ensure container exists with public access (idempotent; won't fail if exists)
          az storage container create --name $CONTAINER --account-name $STORAGE_ACCOUNT --public-access blob --auth-mode login || true
          
          # Define build-specific and latest paths
          BUILD_DIR="builds/$BUILD_NUMBER"
          LATEST_DIR="latest"
          
          # Upload to build-specific path (directories are created implicitly)
          az storage blob upload --container-name $CONTAINER --name "$BUILD_DIR/pci_dss_drifts.json" --file output/pci_dss_drifts.json --account-name $STORAGE_ACCOUNT --auth-mode login
          az storage blob upload --container-name $CONTAINER --name "$BUILD_DIR/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --auth-mode login
          
          # Upload to 'latest' path (overwrites previous latest)
          az storage blob upload --container-name $CONTAINER --name "$LATEST_DIR/pci_dss_drifts.json" --file output/pci_dss_drifts.json --account-name $STORAGE_ACCOUNT --auth-mode login
          az storage blob upload --container-name $CONTAINER --name "$LATEST_DIR/azure.json" --file output/azure.json --account-name $STORAGE_ACCOUNT --auth-mode login
        '''
      }
    }
  }
}
