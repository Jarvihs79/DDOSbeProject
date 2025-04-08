import dash
from dash import dcc, html, Input, Output, callback
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import requests
from datetime import datetime
import time
import threading
import warnings

# Suppress FutureWarnings
warnings.simplefilter(action='ignore', category=FutureWarning)

# Initialize the Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
server = app.server

# Dashboard layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col(html.H1("Network Anomaly Detection Dashboard", className="text-center mb-4"), width=12)
    ]),

    dbc.Row([
        dbc.Col([
            dcc.Graph(id='live-traffic-graph', className='mb-4', figure=go.Figure(
                layout=dict(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    title='Live Network Traffic (Packets per Second)'
                )
            )),
        ], width=8),

        dbc.Col([
            html.Div(id='alerts-container', className='alert-container mb-4', children=[
                dbc.Alert("Initializing alerts system...", color="info")
            ]),
        ], width=4)
    ]),

    dbc.Row([
        dbc.Col([
            dcc.Graph(id='attack-distribution', className='mb-4', figure=go.Figure(
                layout=dict(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    title='Attack Distribution'
                )
            )),
        ], width=6),

        dbc.Col([
            dcc.Graph(id='protocol-distribution', className='mb-4', figure=go.Figure(
                layout=dict(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    title='Protocol Distribution'
                )
            )),
        ], width=6)
    ]),

    dbc.Row([
        dbc.Col([
            html.Div(id='connection-status', className='mb-2'),
            html.Div(id='stats-container', className='stats-container', children=[
                dbc.Card("Loading network statistics...", body=True, className="text-center")
            ]),
        ], width=12)
    ]),

    dcc.Interval(id='update-interval', interval=2000, n_intervals=0)
], fluid=True, style={'backgroundColor': '#222'})

# Global variables
api_status = {"sniffer": False, "inference": False}


def fetch_data():
    try:
        # Get packet data from sniffer
        packet_response = requests.get("http://localhost:5000/packets", timeout=2)
        if packet_response.status_code == 200:
            packets = packet_response.json().get('packets', [])
            api_status["sniffer"] = True
        else:
            packets = []
            api_status["sniffer"] = False

        # Get predictions from inference API
        pred_response = requests.get("http://localhost:5001/predictions", timeout=2)
        if pred_response.status_code == 200:
            predictions = pred_response.json()
            api_status["inference"] = True
        else:
            predictions = []
            api_status["inference"] = False

        return packets, predictions
    except Exception as e:
        print(f"Data fetch error: {e}")
        api_status["sniffer"] = False
        api_status["inference"] = False
        return [], []


@app.callback(
    [Output('connection-status', 'children'),
     Output('live-traffic-graph', 'figure'),
     Output('protocol-distribution', 'figure'),
     Output('attack-distribution', 'figure'),
     Output('stats-container', 'children'),
     Output('alerts-container', 'children')],
    [Input('update-interval', 'n_intervals')]
)
def update_dashboard(n):
    # Connection status
    status = [
        dbc.Badge(
            f"Sniffer API: {'Connected' if api_status['sniffer'] else 'Disconnected'}",
            color="success" if api_status['sniffer'] else "danger",
            className="me-2"
        ),
        dbc.Badge(
            f"Inference API: {'Connected' if api_status['inference'] else 'Disconnected'}",
            color="success" if api_status['inference'] else "danger",
            className="me-2"
        )
    ]

    # Initialize components
    traffic_fig = go.Figure()
    protocol_fig = go.Figure()
    attack_fig = go.Figure()
    stats = dbc.Card("Waiting for data...", body=True, className="text-center")
    alerts = dbc.Alert("No alerts yet", color="info")

    # Fetch data
    packets, predictions = fetch_data()

    # Process traffic graph
    if packets and 'timestamp' in packets[0] and 'size' in packets[0]:
        try:
            df = pd.DataFrame(packets)
            df['timestamp'] = pd.to_datetime(df['timestamp'], format='%H:%M:%S.%f', errors='coerce')
            df = df.dropna(subset=['timestamp'])
            if not df.empty:
                df = df.set_index('timestamp')
                traffic = df['size'].resample('1s').count()
                traffic_fig = go.Figure(
                    go.Scatter(
                        x=traffic.index,
                        y=traffic.values,
                        mode='lines+markers',
                        name='Packets/sec',
                        line=dict(color='#00bc8c')
                    )
                )
                traffic_fig.update_layout(
                    title='Live Network Traffic',
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    margin=dict(l=20, r=20, t=40, b=20)
                )
        except Exception as e:
            print(f"Traffic graph error: {e}")

    # Process protocol distribution
    if packets and 'protocol' in packets[0]:
        try:
            df = pd.DataFrame(packets)
            protocol_counts = df['protocol'].value_counts().reset_index()
            protocol_counts.columns = ['protocol', 'count']
            protocol_counts = protocol_counts[protocol_counts['protocol'] != 'Unknown']
            if not protocol_counts.empty:
                protocol_fig = px.bar(
                    protocol_counts,
                    x='protocol',
                    y='count',
                    title='Protocol Distribution',
                    color='protocol',
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                protocol_fig.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                    margin=dict(l=20, r=20, t=40, b=20)
                )
        except Exception as e:
            print(f"Protocol error: {e}")

    # Process attack distribution
    if predictions and len(predictions) > 0 and 'is_attack' in predictions[0]:
        try:
            df = pd.DataFrame(predictions)
            if df['is_attack'].nunique() > 1:
                attack_counts = df['is_attack'].value_counts().reset_index()
                attack_counts.columns = ['is_attack', 'count']
                attack_fig = px.pie(
                    attack_counts,
                    names=['Normal' if not x else 'Attack' for x in attack_counts['is_attack']],
                    values='count',
                    title='Attack Distribution'
                )
            else:
                attack_fig = go.Figure()
                attack_fig.add_annotation(
                    text="All traffic normal" if df['is_attack'].iloc[0] == False
                    else "All traffic flagged as attacks",
                    x=0.5, y=0.5, showarrow=False
                )
            attack_fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
        except Exception as e:
            print(f"Attack distribution error: {e}")

    # Process stats
    if packets and predictions:
        try:
            packet_df = pd.DataFrame(packets)
            pred_df = pd.DataFrame(predictions)
            stats = dbc.Card([
                dbc.CardHeader("Network Statistics"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.H4(f"{len(packet_df):,}", className="text-center"),
                            html.P("Total Packets", className="text-center text-muted mb-0")
                        ]),
                        dbc.Col([
                            html.H4(f"{pred_df['is_attack'].sum():,}", className="text-center text-danger"),
                            html.P("Attack Packets", className="text-center text-muted mb-0")
                        ]),
                        dbc.Col([
                            html.H4(f"{pred_df['is_attack'].mean() * 100:.1f}%", className="text-center"),
                            html.P("Attack %", className="text-center text-muted mb-0")
                        ])
                    ])
                ])
            ], className="shadow")
        except Exception as e:
            print(f"Stats error: {e}")

    # Process alerts
    if predictions:
        try:
            alert_list = []
            for pred in predictions[-3:]:
                if isinstance(pred, dict) and pred.get('is_attack', False):
                    alert_list.append(
                        dbc.Alert(
                            f"🚨 Attack detected at {pred.get('timestamp', 'unknown')}",
                            color="danger",
                            className="mb-2"
                        )
                    )
            alerts = html.Div(alert_list if alert_list else [
                dbc.Alert("No current threats", color="success")
            ])
        except Exception as e:
            print(f"Alerts error: {e}")

    return status, traffic_fig, protocol_fig, attack_fig, stats, alerts


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8050, debug=True)