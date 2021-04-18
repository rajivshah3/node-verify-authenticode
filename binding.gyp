{
  'conditions': [
    ['OS=="win"', {
        'targets': [
            {
                'target_name': 'verify-authenticode-native',
                'sources': ['src/verify_authenticode.cc'],
                'include_dirs': ["<!@(node -p \"require('node-addon-api').include\")"],
                'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"],
                'cflags!': ['-fno-exceptions'],
                'cflags_cc!': ['-fno-exceptions'],
                'cflags+': ['-Wall'],
                'msvs_settings': {
                    'VCCLCompilerTool': {'ExceptionHandling': 1},
                }
            }
        ]
    }]
  ]
}
