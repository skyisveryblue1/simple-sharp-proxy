﻿using System.Text;
using Titanium.Web.Proxy.EventArguments;

namespace Sharp.Proxy
{
    public static class ProxyEventArgsBaseExtensions
    {
        public static SampleClientState GetState(this ProxyEventArgsBase args)
        {
            if (args.ClientUserData == null) args.ClientUserData = new SampleClientState();

            return (SampleClientState)args.ClientUserData;
        }
    }

    public class SampleClientState
    {
        public StringBuilder PipelineInfo { get; } = new StringBuilder();
    }
}