const matchesCallbackUrl = (url, callbackUrl) => {
  return url ? url.href.startsWith(callbackUrl.href) : false;
};

module.exports = { matchesCallbackUrl };
