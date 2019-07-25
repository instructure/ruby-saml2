#! /usr/bin/env groovy

pipeline {
  agent { label 'docker' }

  stages {
    stage('Build') {
      steps {
        sh 'docker build -t saml2 .'
      }
    }
    stage('Test') {
      steps {
        sh 'docker run --rm saml2 bundle exec rspec'
      }
    }
  }
}
