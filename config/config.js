module.exports = {
  name: 'SnapAttack',
  acronym: 'SNAP',
  onDemandOnly: true,
  description: '',
  entityTypes: ['cve'],
  customTypes: [
    {
      key: 'allText',
      regex: /\S[\s\S]{3,30}\S/
    }
  ],
  styles: ['./styles/styles.less'],
  block: {
    component: {
      file: './components/block.js'
    },
    template: {
      file: './templates/block.hbs'
    }
  },
  defaultColor: 'light-gray',
  request: {
    cert: '',
    key: '',
    passphrase: '',
    ca: '',
    proxy: ''
  },
  logging: {
    level: 'info'
  },
  options: [
    {
      key: 'apiKey',
      name: 'API KEY',
      description: 'Your SnapAttack API key',
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'lookups',
      name: 'Data to Lookup in the SnapAttack Integration',
      description: 'Lookup information on Vulnerabilities, Threat Actors or MITRE Attack.',
      default: {
        value: 'threatActors',
        display: 'Lookup information on Threat Actors in SnapAttack (default)'
      },
      type: 'select',
      options: [
        {
          value: 'threatActors',
          display: 'Lookup information on Threat Actors in SnapAttack'
        },
        {
          value: 'mitre',
          display: 'Lookup information on MITRE attack techniques in SnapAttack'
        }
      ],
      multiple: false,
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
