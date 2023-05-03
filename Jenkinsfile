#! /usr/bin/env groovy

pipeline {
  agent { label 'docker' }

  stages {
    stage('Build') {
      steps {
        sh 'docker build -t saml2 .'
      }
    }
    stage('Lint') {
      steps {
        sh 'docker run --rm saml2 bin/rubocop'
      }
    }
    stage('Test') {
      steps {
        sh 'docker run --rm saml2 bin/rspec'
      }
    }
  }
}
