pipeline {
  agent any

  environment {
    TF_IN_AUTOMATION = 'true'
    TF_INPUT = 'false'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Terraform Init & Plan') {
      steps {
        sh '''
          cd terraform
          terraform init -input=false
          terraform plan -out=tfplan.out
          terraform show -json tfplan.out > tfplan.json
        '''
      }
    }

    stage('OPA / Rego Compliance Check') {
      steps {
        sh '''
          conftest test --parser terraform-plan terraform/tfplan.json -p policy
        '''
      }
    }

    stage('Checkov Static Scan') {
      steps {
        sh '''
          checkov -d terraform --framework terraform --quiet
        '''
      }
    }
  }
}
