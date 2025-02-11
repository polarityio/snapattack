module.exports = {
  name: 'SnapAttack',
  acronym: 'SNAP',
  onDemandOnly: true,
  description: 'Lookup information on CVEs and either tagged Threat Actor names or tagged MITRE ATT&CK techniques',
  entityTypes: ['cve'],
  customTypes: [
    {
      key: 'allText',
      regex: /\b.{3,100}\b/
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
      description: 'Lookup information on tagged Threat Actors or MITRE Attack.',
      default: {
        value: 'threatActors',
        display: 'Lookup information on tagged Threat Actors in SnapAttack (default)'
      },
      type: 'select',
      options: [
        {
          value: 'threatActors',
          display: 'Lookup information on tagged Threat Actors in SnapAttack'
        },
        {
          value: 'mitre',
          display: 'Lookup information on tagged MITRE attack techniques in SnapAttack'
        }
      ],
      multiple: false,
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
