const path = require('path');

module.exports = {
	mode: 'development', 
  entry: './src/index.tsx',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js',
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
   devServer: {
    static: {
      directory: path.join(__dirname, 'public'), // 替代 contentBase
    },
    compress: true,
    port: 9000,
    // 其他選項
  },
};
